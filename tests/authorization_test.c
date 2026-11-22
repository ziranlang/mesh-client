#include MESH_AUTHORIZATION_HEADER
#include MESH_AUTHORIZATION_OWNER_HEADER
#include MESH_DELEGATED_HEADER
#include MESH_ASYNC_DELEGATED_HEADER
#include MESH_ENVELOPE_HEADER
#include "json_scan.h"
#include MESH_CRYPTO_HEADER
#include "zir_string.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char fixture[40000], answer[18000], challenge_json[2048];
static char session_signature[129], expected_session_message[1024];
static char proof_message[2048], proof_signature[129];
static GrantStorage original, verified;
static RequestedScope wanted[1];
static DelegateClient client;
static int transfers, polls, stage, cancels, nonce_counter;
static int response_status;
static bool active, failed_transport;
static int64_t clock_now = 1791400000;
static int64_t server_advance, challenge_delivery_delay, session_delivery_delay, sign_advance;
static bool dynamic_timing;

typedef struct {
    TelegramDelegateOperation operation;
    const char *method, *path, *query, *invoice_id, *body;
    int32_t status;
} TelegramRequestCase;

static const TelegramRequestCase telegram_cases[] = {
    {TelegramDelegateOperation_Launch, "POST", "/api/v1/telegram/launch", "", "",
        "{\"app_id\":\"inbe\",\"init_data\":\"synthetic\"}", 200},
    {TelegramDelegateOperation_Catalog, "GET", "/api/v1/tokens/purchases/telegram/catalog", "app_id=inbe", "", "", 200},
    {TelegramDelegateOperation_Balance, "GET", "/api/v1/tokens/purchases/telegram/balance", "app_id=inbe", "", "", 200},
    {TelegramDelegateOperation_CreateInvoice, "POST", "/api/v1/tokens/purchases/telegram/invoices", "", "",
        "{\"app_id\":\"inbe\",\"init_data\":\"synthetic\",\"product_id\":\"dew_10\",\"request_id\":\"test-order\"}", 201},
    {TelegramDelegateOperation_InvoiceStatus, "GET", "/api/v1/tokens/purchases/telegram/invoices/0123456789abcdef0123456789abcdef",
        "", "0123456789abcdef0123456789abcdef", "", 200},
    {TelegramDelegateOperation_CancelInvoice, "POST", "/api/v1/tokens/purchases/telegram/invoices/0123456789abcdef0123456789abcdef/cancel",
        "", "0123456789abcdef0123456789abcdef", "", 200},
};

static const TelegramRequestCase *expected_telegram_request;
static char telegram_signed_message[2048];
static int64_t current_time(void *context)
{
    (void)context;
    return clock_now;
}

static void replace_number(char *json, const char *name, int64_t value)
{
    char key[64];
    snprintf(key, sizeof key, "\"%s\"", name);
    char *found = strstr(json, key);
    assert(found);
    char *start = strchr(found, ':') + 1;
    while (*start == ' ') {
        start++;
    }
    char *end = start;
    while (*end >= '0' && *end <= '9') {
        end++;
    }
    char number[32];
    snprintf(number, sizeof number, "%lld", (long long)value);
    size_t count = strlen(number);
    memmove(start + count, end, strlen(end) + 1);
    memcpy(start, number, count);
}

static String text(const char *value)
{
    return StringView(value, strlen(value));
}

static Slice bytes(void *value, size_t size)
{
    return (Slice){.data = value, .length = size};
}

static void copy_output(Slice output, const char *value)
{
    assert(strlen(value) < (size_t)output.length);
    memcpy(output.data, value, strlen(value) + 1);
}

static String object(String document, const char *name)
{
    int32_t start = FieldAt(document, 0, text(name));
    int32_t end = ValueEnd(document, start, 0);
    assert(start >= 0 && end > start);
    return StringView(document.data + start, (uint64_t)(end - start));
}

static void field(String document, const char *name, char *output, size_t size)
{
    int32_t start = FieldAt(document, 0, text(name));
    assert(ReadStringText(document, start, bytes(output, size)) >= 0);
}

static bool sign_delegate(void *context, String message, Slice output)
{
    (void)context;
    assert(message.length > 20);
    if (StringEqual(message, text(expected_session_message))) {
        copy_output(output, session_signature);
    } else {
        if (expected_telegram_request && message.length < sizeof telegram_signed_message) {
            memcpy(telegram_signed_message, message.data, message.length);
            telegram_signed_message[message.length] = 0;
        }
        clock_now += sign_advance;
        memset(output.data, 'a', 128);
        ((char *)output.data)[128] = 0;
    }
    return true;
}

static bool random_id(void *context, Slice output)
{
    (void)context;
    assert(output.length >= 33);
    nonce_counter++;
    memset(output.data, '9', 32);
    ((char *)output.data)[31] = (char)('0' + nonce_counter % 10);
    ((char *)output.data)[32] = 0;
    return true;
}

static bool start(void *context, HttpRequest request, Slice output)
{
    (void)context;
    assert(!active);
    assert(request.token.length == 0);
    assert(StringEqual(request.method, StringLiteral("POST")));
    active = true;
    transfers++;
    polls = 0;
    const char *url = request.url.data;
    if (strstr(url, "/authorization/challenge")) {
        stage = 1;
        assert(request.headers.length == 0);
        clock_now += server_advance;
        char current[2048];
        strcpy(current, challenge_json);
        if (dynamic_timing) {
            replace_number(current, "expires_at", clock_now + 90);
        }
        copy_output(output, current);
    } else if (strstr(url, "/authorization/session")) {
        stage = 2;
        assert(request.headers.length == 0);
        clock_now += server_advance;
        char current[18000];
        strcpy(current, answer);
        if (dynamic_timing) {
            replace_number(current, "expires_at", clock_now + 300);
        }
        copy_output(output, current);
    } else {
        stage = 3;
        assert(strstr(url, "/delegated/sync"));
        assert(request.headers.length == 2);
        HttpHeader *headers = request.headers.data;
        assert(StringEqual(headers[0].name, StringLiteral("Authorization")));
        assert(strncmp(headers[0].value.data, "Delegate ds1.", 13) == 0);
        assert(StringEqual(headers[1].name, StringLiteral("X-Mesh-Delegate")));
        assert(strstr(headers[1].value.data, "\"node_id\":"));
        copy_output(output, "{\"collection\":\"private.inbe.v2.lumi\",\"records\":[],\"next_version\":1,\"truncated\":false,\"applied\":0}");
    }
    return true;
}

static bool start_telegram(void *context, HttpRequest request, Slice output)
{
    const TelegramRequestCase *expected = expected_telegram_request;
    assert(expected);
    if (strstr(request.url.data, "/api/v1/authorization/")) {
        return start(context, request, output);
    }
    DelegateClient *linked = context;
    assert(!active && request.token.length == 0 && request.headers.length == 2);
    assert(StringEqual(request.method, text(expected->method)) && StringEqual(request.body, text(expected->body)));
    char url[768];
    int length = snprintf(url, sizeof url, "%.*s%s%s%s", (int)linked->audience.length, linked->audience.data,
        expected->path, *expected->query ? "?" : "", expected->query);
    assert(length > 0 && length < (int)sizeof url && StringEqual(request.url, text(url)));
    HttpHeader *headers = request.headers.data;
    assert(StringEqual(headers[0].name, text("Authorization")) && headers[0].value.length == 45);
    assert(strncmp(headers[0].value.data, "Delegate ds1.", 13) == 0);
    assert(StringEqual(headers[1].name, text("X-Mesh-Delegate")));
    String proof = headers[1].value;
    char method[8], path[105], query[72], digest[65], computed[65], nonce[33], challenge[33];
    field(proof, "method", method, sizeof method);
    field(proof, "path", path, sizeof path);
    field(proof, "query", query, sizeof query);
    field(proof, "body_sha256", digest, sizeof digest);
    field(proof, "nonce", nonce, sizeof nonce);
    field(proof, "challenge", challenge, sizeof challenge);
    Sha256Hex((uint8_t *)expected->body, strlen(expected->body), (uint8_t *)computed);
    assert(strcmp(method, expected->method) == 0 && strcmp(path, expected->path) == 0 && strcmp(query, expected->query) == 0);
    assert(strcmp(digest, computed) == 0);
    int64_t expires;
    assert(MESH_AUTHORIZATION_SYMBOL(ReadInteger)(proof, FieldAt(proof, 0, text("expires_at")), &expires));
    assert(expires > clock_now && expires <= clock_now + 60);
    char canonical[2048];
    length = snprintf(canonical, sizeof canonical,
        "daochi-delegate-request-v1\n1\n%s\n%.32s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%lld\n%s\n",
        (char *)linked->grant->grant_id, headers[0].value.data + 13, (char *)linked->grant->account_id,
        (char *)linked->grant->app_id, (char *)linked->grant->client_id, (char *)linked->grant->node_id,
        (char *)linked->grant->audience, challenge,
        method, path, query, digest, (long long)expires, nonce);
    assert(length > 0 && length < (int)sizeof canonical && strcmp(canonical, telegram_signed_message) == 0);
    active = true;
    transfers++;
    polls = 0;
    stage = 3;
    copy_output(output, "{\"fixture\":true}");
    return true;
}

static int32_t poll(void *context, int32_t *status)
{
    (void)context;
    assert(active);
    if (++polls == 1) {
        return -1;
    }
    active = false;
    if (stage == 1) {
        clock_now += challenge_delivery_delay;
    }
    if (stage == 2) {
        clock_now += session_delivery_delay;
    }
    *status = stage == 3 ? response_status : 200;
    return failed_transport ? 0 : 1;
}

static void cancel(void *context)
{
    (void)context;
    assert(active);
    active = false;
    cancels++;
}

static bool send(void *context, HttpRequest request, Slice output, int32_t *status)
{
    if (!start(context, request, output)) {
        return false;
    }
    int32_t result;
    do {
        result = poll(context, status);
    } while (result < 0);
    return result != 0;
}

static bool start_async(void *closure, void *context, HttpRequest request, Slice output)
{
    (void)closure;
    return start(context, request, output);
}
static bool start_telegram_async(void *closure, void *context, HttpRequest request, Slice output)
{
    (void)closure;
    return start_telegram(context, request, output);
}
static int32_t poll_async(void *closure, void *context, int32_t *status)
{
    (void)closure;
    return poll(context, status);
}
static void cancel_async(void *closure, void *context)
{
    (void)closure;
    cancel(context);
}

static void configure(String document)
{
    String response = object(document, "answer");
    assert(response.length < sizeof answer);
    memcpy(answer, response.data, response.length);
    answer[response.length] = 0;
    assert(MESH_AUTHORIZATION_SYMBOL(ReadGrantAt)(object(response, "grant"), 0, &original));
    String challenge = object(document, "challenge");
    memcpy(challenge_json, challenge.data, challenge.length);
    challenge_json[challenge.length] = 0;
    field(document, "challenge_message", expected_session_message, sizeof expected_session_message);
    field(document, "proof_message", proof_message, sizeof proof_message);
    field(object(document, "proof"), "signature", proof_signature, sizeof proof_signature);
    /* The host signer remains explicit. Wire canonicalization is fixture tested;
       real Ed25519 verification of these signatures is performed by the server. */
    memset(session_signature, 'a', 128);
    session_signature[128] = 0;
    wanted[0] = (RequestedScope){.collection = StringLiteral("private.inbe.v2.lumi"),
        .read = true, .write = true};
    client = (DelegateClient){
        .server_url = text((char *)original.audience),
        .account_id = text((char *)original.account_id),
        .app_id = text((char *)original.app_id),
        .client_id = text((char *)original.client_id),
        .grant_id = text((char *)original.grant_id),
        .node_id = text((char *)original.node_id),
        .audience = text((char *)original.audience),
        .signing_key = text((char *)original.signing_key),
        .encryption_key = text((char *)original.encryption_key),
        .scopes = bytes(wanted, 1), .grant = &verified,
        .signer = sign_delegate, .random = random_id, .send = send, .clock = current_time,
        .bot_id = original.bot_id, .telegram_id = original.telegram_id,
    };
}

static void check_messages(String document)
{
    GrantScope scopes[16];
    Grant grant = {0};
    assert(MESH_AUTHORIZATION_SYMBOL(ViewGrant)(&original, bytes(scopes, 16), &grant));
    char output[12000], expected[12000];
    assert(MESH_AUTHORIZATION_SYMBOL(BuildGrantMessage)(grant, bytes(output, sizeof output)));
    field(document, "grant_message", expected, sizeof expected);
    assert(strcmp(output, expected) == 0);
    String response = object(document, "answer");
    char public_key[2625];
    field(response, "owner_public_key", public_key, sizeof public_key);
    assert(MESH_AUTHORIZATION_SYMBOL(VerifyGrantSignature)(grant, text(public_key), 1791400000));
    grant.app_id = StringLiteral("other");
    assert(!MESH_AUTHORIZATION_SYMBOL(VerifyGrantSignature)(grant, text(public_key), 1791400000));
    grant.app_id = StringLiteral("inbe");
    scopes[0].key_id = StringLiteral("inbe-lumi-2");
    assert(!MESH_AUTHORIZATION_SYMBOL(VerifyGrantSignature)(grant, text(public_key), 1791400000));
    assert(MESH_AUTHORIZATION_SYMBOL(ViewGrant)(&original, bytes(scopes, 16), &grant));
    grant.node_id = grant.client_id;
    assert(!MESH_AUTHORIZATION_SYMBOL(VerifyGrantSignature)(grant, text(public_key), 1791400000));
    assert(MESH_AUTHORIZATION_SYMBOL(ViewGrant)(&original, bytes(scopes, 16), &grant));
    assert(!MESH_AUTHORIZATION_SYMBOL(VerifyGrantSignature)(grant, text(public_key), grant.expires_at));
    SessionChallenge challenge;
    assert(MESH_AUTHORIZATION_SYMBOL(ReadChallenge)(text(challenge_json), &challenge));
    assert(MESH_DELEGATED_SYMBOL(BuildSessionMessage)(&challenge, bytes(output, sizeof output)));
    field(document, "challenge_message", expected, sizeof expected);
    assert(strcmp(output, expected) == 0);
    String proof = object(document, "proof");
    char body_hash[65], nonce[33];
    field(proof, "body_sha256", body_hash, sizeof body_hash);
    field(proof, "nonce", nonce, sizeof nonce);
    RequestProof request = {
        .grant_id = client.grant_id, .session_id = StringLiteral("77777777777777777777777777777777"),
        .account_id = client.account_id, .app_id = client.app_id, .client_id = client.client_id,
        .node_id = client.node_id, .audience = client.audience,
        .challenge = StringLiteral("88888888888888888888888888888888"),
        .method = StringLiteral("POST"), .path = StringLiteral("/api/v1/delegated/sync"),
        .query = StringLiteral(""), .body_sha256 = text(body_hash), .expires_at = 1791400030,
        .nonce = text(nonce),
    };
    assert(MESH_DELEGATED_SYMBOL(BuildProofMessage)(request, bytes(output, sizeof output)));
    assert(strcmp(output, proof_message) == 0);
    request.path = StringLiteral("/api/v1/account/delete");
    assert(!MESH_DELEGATED_SYMBOL(BuildProofMessage)(request, bytes(output, sizeof output)));
    request.path = StringLiteral("/api/v1/sync");
    assert(!MESH_DELEGATED_SYMBOL(BuildProofMessage)(request, bytes(output, sizeof output)));
    assert(!MESH_DELEGATED_SYMBOL(RequestRoute)(StringLiteral("GET"), StringLiteral("/api/v1/delegated/ws"),
        StringLiteral("collection=private.inbe.v2.lumi&token=stolen")));
    assert(!MESH_AUTHORIZATION_SYMBOL(Collection)(StringLiteral("private.inbe.v1.cells")));
    assert(!MESH_AUTHORIZATION_SYMBOL(Collection)(StringLiteral("account.keys")));
    assert(!MESH_AUTHORIZATION_SYMBOL(Collection)(StringLiteral("private.inbe.v1.sessions")));
    PublicRendezvous pending;
    assert(MESH_AUTHORIZATION_SYMBOL(ReadPublicRendezvous)(object(document, "public_pending"), &pending));
    assert(!MESH_AUTHORIZATION_SYMBOL(ReadPublicRendezvous)(object(document, "pending"), &pending));
    assert(MESH_AUTHORIZATION_SYMBOL(ReadPublicRendezvous)(object(document, "public_pending"), &pending));
    assert(MESH_AUTHORIZATION_SYMBOL(BuildClaimMessage)(&pending, client.client_id, client.signing_key,
        client.encryption_key, StringLiteral(""), bytes(output, sizeof output)));
    field(document, "claim_message", expected, sizeof expected);
    assert(strcmp(output, expected) == 0);
    assert(!MESH_AUTHORIZATION_SYMBOL(BuildClaimMessage)(&pending, StringLiteral("malformed"), client.signing_key,
        client.encryption_key, StringLiteral(""), bytes(output, sizeof output)));
}

static void check_acceptance(void)
{
    DelegateSession session;
    assert(MESH_DELEGATED_SYMBOL(AcceptSessionAnswer)(client, 200, text(answer), 1791400000, &session) == AuthResult_AUTH_OK);
    assert(MESH_DELEGATED_SYMBOL(SessionValid)(client, &session, 1791400000));
    DelegateClient wrong = client;
    wrong.account_id = client.client_id;
    assert(MESH_DELEGATED_SYMBOL(AcceptSessionAnswer)(wrong, 200, text(answer), 1791400000, &session) == AuthResult_AUTH_FAILED);
    assert(!session.session_id[0]);
    wrong = client;
    wrong.node_id = client.client_id;
    assert(MESH_DELEGATED_SYMBOL(AcceptSessionAnswer)(wrong, 200, text(answer), 1791400000, &session) == AuthResult_AUTH_FAILED);
    wrong = client;
    wrong.signing_key = client.client_id;
    assert(MESH_DELEGATED_SYMBOL(AcceptSessionAnswer)(wrong, 200, text(answer), 1791400000, &session) == AuthResult_AUTH_FAILED);
    wanted[0].write = false;
    assert(MESH_DELEGATED_SYMBOL(AcceptSessionAnswer)(client, 200, text(answer), 1791400000, &session) == AuthResult_AUTH_FAILED);
    wanted[0].write = true;
    clock_now = 1791400300;
    assert(MESH_DELEGATED_SYMBOL(AcceptSessionAnswer)(client, 200, text(answer), 1791400000, &session) == AuthResult_AUTH_FAILED);
    clock_now = 1791400000;
    assert(MESH_DELEGATED_SYMBOL(AcceptSessionAnswer)(client, 401, text(answer), 1791400000, &session) == AuthResult_AUTH_FAILED);
    char mutated[18000];
    strcpy(mutated, answer);
    char *signature = strstr(mutated, "\"signature\"");
    assert(signature);
    signature = strchr(strchr(signature, ':') + 1, '"') + 1;
    *signature = *signature == '0' ? '1' : '0';
    assert(MESH_DELEGATED_SYMBOL(AcceptSessionAnswer)(client, 200, text(mutated), 1791400000, &session) == AuthResult_AUTH_FAILED);
    strcpy(mutated, answer);
    char *generation = strstr(mutated, "inbe-lumi-1");
    assert(generation);
    generation[10] = '2';
    assert(MESH_DELEGATED_SYMBOL(AcceptSessionAnswer)(client, 200, text(mutated), 1791400000, &session) == AuthResult_AUTH_FAILED);
    int32_t offsets[2];
    String names[] = {StringLiteral("key"), StringLiteral("other")};
    assert(!MESH_AUTHORIZATION_SYMBOL(ObjectFields)(StringLiteral("{\"key\":1,\"\\u006bey\":2,\"other\":3}"),
        0, bytes(names, 2), bytes(offsets, 2)));
    assert(!MESH_AUTHORIZATION_SYMBOL(WholeJson)(StringLiteral("{} trailing")));
}

static void reject_open(Grant grant, GrantScope scope, EncryptionKeys *keys,
    uint8_t output[32])
{
    memset(output, 0x42, 32);
    assert(!MESH_ENVELOPE_SYMBOL(OpenCollectionKey)(grant, scope, keys, bytes(output, 32)));
    for (size_t i = 0; i < 32; i++) {
        assert(output[i] == 0);
    }
}

static void check_envelopes(void)
{
    EncryptionKeys recipient, other;
    assert(MESH_ENVELOPE_SYMBOL(CreateEncryptionKeys)(&recipient));
    assert(MESH_ENVELOPE_SYMBOL(CreateEncryptionKeys)(&other));
    char public_hex[2369], opaque[4096];
    assert(MESH_ENVELOPE_SYMBOL(EncryptionPublicHex)(&recipient, bytes(public_hex, sizeof public_hex)));
    GrantScope scopes[16];
    Grant grant = {0};
    assert(MESH_AUTHORIZATION_SYMBOL(ViewGrant)(&original, bytes(scopes, 16), &grant));
    grant.encryption_key = text(public_hex);
    uint8_t key[32], opened[32];
    memset(key, 0x42, sizeof key);
    assert(MESH_ENVELOPE_SYMBOL(SealCollectionKey)(grant, scopes[0], bytes(key, 32), bytes(opaque, sizeof opaque)));
    scopes[0].key_envelope = text(opaque);
    assert(MESH_ENVELOPE_SYMBOL(OpenCollectionKey)(grant, scopes[0], &recipient, bytes(opened, 32)));
    assert(memcmp(key, opened, 32) == 0);
    memset(opened, 0x42, sizeof opened);
    reject_open(grant, scopes[0], NULL, opened);
    for (size_t i = 0; i < 32; i++) {
        assert(opened[i] == 0);
    }
    String valid_envelope = scopes[0].key_envelope;
    scopes[0].key_envelope = StringLiteral("malformed");
    memset(opened, 0x42, sizeof opened);
    reject_open(grant, scopes[0], &recipient, opened);
    for (size_t i = 0; i < 32; i++) {
        assert(opened[i] == 0);
    }
    scopes[0].key_envelope = valid_envelope;
    reject_open(grant, scopes[0], &other, opened);
    EncryptionKeys mismatched = other;
    memcpy(mismatched.public_key, recipient.public_key, sizeof mismatched.public_key);
    reject_open(grant, scopes[0], &mismatched, opened);
    MESH_ENVELOPE_SYMBOL(ClearEncryptionKeys)(&mismatched);
    for (size_t i = 0; i < 32; i++) {
        assert(opened[i] == 0);
    }
    scopes[0].key_id = StringLiteral("inbe-lumi-2");
    reject_open(grant, scopes[0], &recipient, opened);
    scopes[0].key_id = StringLiteral("inbe-lumi-1");
    scopes[0].collection = StringLiteral("private.inbe.v1.sessions");
    reject_open(grant, scopes[0], &recipient, opened);
    scopes[0].collection = StringLiteral("private.inbe.v2.lumi");
    char *ciphertext = strstr(opaque, "\"ciphertext\"");
    assert(ciphertext);
    ciphertext = strchr(strchr(ciphertext, ':') + 1, '"') + 1;
    *ciphertext = *ciphertext == '0' ? '1' : '0';
    reject_open(grant, scopes[0], &recipient, opened);
    assert(!MESH_ENVELOPE_SYMBOL(SealCollectionKey)(grant, scopes[0], bytes(key, 31), bytes(opaque, sizeof opaque)));
    MESH_ENVELOPE_SYMBOL(ClearEncryptionKeys)(&recipient);
    MESH_ENVELOPE_SYMBOL(ClearEncryptionKeys)(&other);
    for (size_t i = 0; i < 2400; i++) {
        assert(recipient.secret_key[i] == 0);
    }
}

static void check_transports(void)
{
    DelegateSession session = {0};
    char output[18000], body[4096], proof[4096], credential[46];
    int32_t status;
    response_status = 200;
    assert(MESH_DELEGATED_SYMBOL(RenewDelegateSession)(client, &session, 1791400000,
        bytes(output, sizeof output)) == AuthResult_AUTH_OK);
    assert(transfers == 2);
    assert(MESH_DELEGATED_SYMBOL(BuildDelegatedSyncBody)(client, wanted[0].collection, true, 0, 128,
        bytes(NULL, 0), bytes(body, sizeof body)));
    assert(!MESH_DELEGATED_SYMBOL(BuildDelegatedSyncBody)(client, StringLiteral("private.inbe.v1.cells"),
        true, 0, 128, bytes(NULL, 0), bytes(body, sizeof body)));
    assert(!MESH_DELEGATED_SYMBOL(BuildDelegatedSyncBody)(client, StringLiteral("private.inbe.v2.diary"),
        true, 0, 128, bytes(NULL, 0), bytes(body, sizeof body)));
    assert(MESH_DELEGATED_SYMBOL(DelegatedSyncBodyValid)(client, text(body)));
    DelegatedResponseInfo info;
    assert(MESH_DELEGATED_SYMBOL(ReadDelegatedSyncResponse)(client,
        StringLiteral("{\"collection\":\"private.inbe.v2.lumi\",\"records\":[{\"collection\":\"private.inbe.v2.lumi\",\"id\":\"record\",\"key_id\":\"inbe-lumi-1\"}],\"next_version\":1,\"truncated\":false,\"applied\":0}"),
        wanted[0].collection, &info));
    assert(info.record_count == 1);
    assert(!MESH_DELEGATED_SYMBOL(ReadDelegatedSyncResponse)(client,
        StringLiteral("{\"collection\":\"private.inbe.v2.lumi\",\"records\":[{\"collection\":\"private.inbe.v2.lumi\",\"id\":\"record\",\"key_id\":\"inbe-lumi-2\"}],\"next_version\":1,\"truncated\":false,\"applied\":0}"),
        wanted[0].collection, &info));
    assert(!MESH_DELEGATED_SYMBOL(ReadDelegatedSyncResponse)(client,
        StringLiteral("{\"collection\":\"private.inbe.v2.lumi\",\"records\":[{\"collection\":\"private.inbe.v2.diary\",\"id\":\"record\",\"key_id\":\"inbe-lumi-1\"}],\"next_version\":1,\"truncated\":false,\"applied\":0}"),
        wanted[0].collection, &info));
    char escalation[4096];
    strcpy(escalation, body);
    char *scope = strstr(escalation, "private.inbe.v2.lumi");
    assert(scope);
    memcpy(scope, "private.inbe.v1.cell", 19);
    assert(!MESH_DELEGATED_SYMBOL(DelegatedSyncBodyValid)(client, text(escalation)));
        assert(MESH_DELEGATED_SYMBOL(DelegateRequest)(client, &session, 1791400000, text(body),
        bytes(output, sizeof output), &status) == AuthResult_AUTH_OK);
    assert(status == 200);
    assert(MESH_DELEGATED_SYMBOL(PrepareDelegateHeaders)(client, &session, 1791400000,
        StringLiteral("POST"), StringLiteral("/api/v1/delegated/sync"), StringLiteral(""),
        text(body), bytes(proof, sizeof proof), bytes(credential, sizeof credential)) == AuthResult_AUTH_OK);
    char first_nonce[33], second_nonce[33];
    field(text(proof), "nonce", first_nonce, sizeof first_nonce);
    assert(MESH_DELEGATED_SYMBOL(PrepareDelegateHeaders)(client, &session, 1791400000,
        StringLiteral("POST"), StringLiteral("/api/v1/delegated/sync"), StringLiteral(""),
        text(body), bytes(proof, sizeof proof), bytes(credential, sizeof credential)) == AuthResult_AUTH_OK);
    field(text(proof), "nonce", second_nonce, sizeof second_nonce);
    assert(strcmp(first_nonce, second_nonce) != 0);
    AsyncTransport transport = {.start = {.call = start_async},
        .poll = {.call = poll_async}, .cancel = {.call = cancel_async}};
    PendingDelegate pending = {0};
    session = (DelegateSession){0};
    transfers = 0;
    assert(MESH_ASYNC_DELEGATED_SYMBOL(BeginDelegateRequest)(&pending, client, &session, 1791400000,
        transport, text(body), bytes(output, sizeof output)));
    assert(!MESH_ASYNC_DELEGATED_SYMBOL(BeginDelegateRequest)(&pending, client, &session, 1791400000,
        transport, text(body), bytes(output, sizeof output)));
    int ticks = 0;
    while (!MESH_ASYNC_DELEGATED_SYMBOL(PollDelegate)(&pending) && ++ticks < 20) {
    }
    assert(ticks < 20 && !active && transfers == 3 && pending.result == AuthResult_AUTH_OK);
    response_status = 401;
    pending = (PendingDelegate){0};
    assert(MESH_ASYNC_DELEGATED_SYMBOL(BeginDelegateRequest)(&pending, client, &session, 1791400000,
        transport, text(body), bytes(output, sizeof output)));
    while (!MESH_ASYNC_DELEGATED_SYMBOL(PollDelegate)(&pending)) {
    }
    assert(pending.result == AuthResult_AUTH_FAILED && !session.session_id[0]);
    pending = (PendingDelegate){0};
    assert(MESH_ASYNC_DELEGATED_SYMBOL(BeginDelegateSession)(&pending, client, &session, 1791400000,
        transport, bytes(output, sizeof output)));
    MESH_ASYNC_DELEGATED_SYMBOL(CancelDelegate)(&pending);
    MESH_ASYNC_DELEGATED_SYMBOL(CancelDelegate)(&pending);
    assert(cancels == 1 && !active && MESH_ASYNC_DELEGATED_SYMBOL(PollDelegate)(&pending));
    assert(pending.result == AuthResult_AUTH_REQUEST_FAILED);
    pending = (PendingDelegate){0};
    failed_transport = true;
    assert(MESH_ASYNC_DELEGATED_SYMBOL(BeginDelegateSession)(&pending, client, &session, 1791400000,
        transport, bytes(output, sizeof output)));
    while (!MESH_ASYNC_DELEGATED_SYMBOL(PollDelegate)(&pending)) {
    }
    assert(pending.result == AuthResult_AUTH_REQUEST_FAILED && !active);
    assert(!MESH_AUTHORIZATION_OWNER_SYMBOL(OwnerAuthorizationRoute)(StringLiteral("/api/v1/account/delete")));
    assert(MESH_AUTHORIZATION_OWNER_SYMBOL(OwnerAuthorizationRoute)(StringLiteral("/api/v1/authorization/revoke")));
    assert(MESH_AUTHORIZATION_OWNER_SYMBOL(OwnerAuthorizationRoute)(StringLiteral("/api/v1/telegram/account/bind")));
    assert(!MESH_AUTHORIZATION_OWNER_SYMBOL(OwnerAuthorizationRoute)(StringLiteral("/api/v1/telegram/account/bind/extra")));
    assert(!MESH_DELEGATED_SYMBOL(RequestRoute)(StringLiteral("POST"), StringLiteral("/api/v1/telegram/account/bind"), StringLiteral("")));
}

static void reset_timing(void)
{
    active = false;
    failed_transport = false;
    response_status = 200;
    transfers = 0;
    clock_now = 1791400000;
    server_advance = 0;
    challenge_delivery_delay = 0;
    session_delivery_delay = 0;
    sign_advance = 0;
    dynamic_timing = true;
}

static void check_advancing_clock(void)
{
    char output[18000], body[4096], proof[4096], credential[46];
    DelegateSession session = {0};
    reset_timing();
    server_advance = 1;
    assert(MESH_DELEGATED_SYMBOL(RenewDelegateSession)(client, &session, 1,
        bytes(output, sizeof output)) == AuthResult_AUTH_OK);
    assert(clock_now == 1791400002 && session.expires_at == clock_now + 300);
    assert(MESH_DELEGATED_SYMBOL(BuildDelegatedSyncBody)(client, wanted[0].collection, true, 0, 128,
        bytes(NULL, 0), bytes(body, sizeof body)));
    assert(MESH_DELEGATED_SYMBOL(PrepareDelegateHeaders)(client, &session, 1,
        StringLiteral("POST"), StringLiteral("/api/v1/delegated/sync"), StringLiteral(""),
        text(body), bytes(proof, sizeof proof), bytes(credential, sizeof credential)) == AuthResult_AUTH_OK);
    int64_t expiry;
    assert(MESH_AUTHORIZATION_SYMBOL(ReadInteger)(text(proof), FieldAt(text(proof), 0,
        StringLiteral("expires_at")), &expiry));
    assert(expiry == clock_now + 60);
    AsyncTransport transport = {.start = {.call = start_async},
        .poll = {.call = poll_async}, .cancel = {.call = cancel_async}};
    PendingDelegate pending = {0};
    reset_timing();
    server_advance = 1;
    session = (DelegateSession){0};
    assert(MESH_ASYNC_DELEGATED_SYMBOL(BeginDelegateRequest)(&pending, client, &session, 1,
        transport, text(body), bytes(output, sizeof output)));
    while (!MESH_ASYNC_DELEGATED_SYMBOL(PollDelegate)(&pending)) {
    }
    assert(pending.result == AuthResult_AUTH_OK && transfers == 3);
    assert(clock_now == 1791400002);
    reset_timing();
    server_advance = 1;
    session.expires_at = clock_now + 4;
    pending = (PendingDelegate){0};
    assert(MESH_ASYNC_DELEGATED_SYMBOL(BeginDelegateRequest)(&pending, client, &session, 1,
        transport, text(body), bytes(output, sizeof output)));
    while (!MESH_ASYNC_DELEGATED_SYMBOL(PollDelegate)(&pending)) {
    }
    assert(pending.result == AuthResult_AUTH_OK && transfers == 3);
    assert(session.expires_at == clock_now + 300);
    reset_timing();
    challenge_delivery_delay = 91;
    session = (DelegateSession){0};
    assert(MESH_DELEGATED_SYMBOL(RenewDelegateSession)(client, &session, 1,
        bytes(output, sizeof output)) == AuthResult_AUTH_FAILED);
    assert(transfers == 1 && !session.session_id[0]);
    reset_timing();
    session_delivery_delay = 301;
    pending = (PendingDelegate){0};
    assert(MESH_ASYNC_DELEGATED_SYMBOL(BeginDelegateSession)(&pending, client, &session, 1,
        transport, bytes(output, sizeof output)));
    while (!MESH_ASYNC_DELEGATED_SYMBOL(PollDelegate)(&pending)) {
    }
    assert(pending.result == AuthResult_AUTH_FAILED && transfers == 2 && !session.session_id[0]);
    reset_timing();
    assert(MESH_DELEGATED_SYMBOL(RenewDelegateSession)(client, &session, 1,
        bytes(output, sizeof output)) == AuthResult_AUTH_OK);
    transfers = 0;
    sign_advance = 61;
    int32_t status;
    assert(MESH_DELEGATED_SYMBOL(DelegateRequest)(client, &session, 1, text(body),
        bytes(output, sizeof output), &status) == AuthResult_AUTH_SIGN_FAILED);
    assert(transfers == 0);
    sign_advance = 0;
    clock_now = 0;
    assert(!MESH_DELEGATED_SYMBOL(SessionValid)(client, &session, 1791400000));
    assert(MESH_DELEGATED_SYMBOL(RenewDelegateSession)(client, &session, 1791400000,
        bytes(output, sizeof output)) == AuthResult_AUTH_PAYLOAD_FAILED);
    DelegateClient no_clock = client;
    no_clock.clock = NULL;
    assert(!MESH_DELEGATED_SYMBOL(DelegateClientValid)(no_clock));
    assert(MESH_DELEGATED_SYMBOL(RenewDelegateSession)(no_clock, &session, 1791400000,
        bytes(output, sizeof output)) == AuthResult_AUTH_PAYLOAD_FAILED);
    reset_timing();
    dynamic_timing = false;
}

static void check_telegram_async(DelegateClient *linked, DelegateSession *session, bool stars)
{
    PendingDelegate pending = {0};
    AsyncTransport transport = {.context = linked, .start = {.call = start_telegram_async},
        .poll = {.call = poll_async}, .cancel = {.call = cancel_async}};
    char output[18000], proof[4096] = "previous", credential[46] = "previous";
    assert(MESH_DELEGATED_SYMBOL(DelegateTelegramStarsAllowed)(*linked) == stars);
    for (size_t i = 0; i < sizeof telegram_cases / sizeof telegram_cases[0]; i++) {
        const TelegramRequestCase *test = &telegram_cases[i];
        expected_telegram_request = test;
        response_status = test->status;
        int before = transfers;
        assert(MESH_ASYNC_DELEGATED_SYMBOL(BeginTelegramDelegateRequest)(&pending, *linked, session, transport,
            test->operation, text(test->invoice_id), text(test->body), bytes(output, sizeof output)));
        if (stars || test->operation == TelegramDelegateOperation_Launch) {
            assert(!MESH_ASYNC_DELEGATED_SYMBOL(PollDelegate)(&pending));
            assert(MESH_ASYNC_DELEGATED_SYMBOL(PollDelegate)(&pending));
            assert(pending.result == AuthResult_AUTH_OK && pending.status == test->status && transfers == before + 1);
            assert(strcmp(output, "{\"fixture\":true}") == 0 && pending.body.length == 0);
        } else {
            assert(MESH_ASYNC_DELEGATED_SYMBOL(PollDelegate)(&pending));
            assert(pending.result == AuthResult_AUTH_FAILED && transfers == before);
        }
    }
    assert(MESH_DELEGATED_SYMBOL(PrepareDelegateHeaders)(*linked, session, 0, text("GET"), text(telegram_cases[2].path),
        text("app_id=inbe"), text(""), bytes(proof, sizeof proof), bytes(credential, sizeof credential)) != AuthResult_AUTH_OK);
    const char *bad[][4] = {
        {"POST", "/api/v1/tokens/purchases/telegram/balance", "app_id=inbe", ""},
        {"GET", "/api/v1/tokens/purchases/telegram/balance", "app_id=other", ""},
        {"GET", "/api/v1/tokens/purchases/telegram/balance", "app_id=inbe&app_id=inbe", ""},
        {"GET", "/api/v1/tokens/balance", "app_id=inbe", ""},
        {"POST", "/api/v1/tokens/purchases/telegram/invoices/0123456789abcdef0123456789abcdef", "", ""},
        {"GET", "/api/v1/tokens/purchases/telegram/invoices/0123456789abcdef0123456789abcdef/cancel", "", ""},
        {"POST", "/api/v1/telegram/launch", "", "{\"app_id\":\"other\",\"init_data\":\"synthetic\"}"},
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        assert(MESH_DELEGATED_SYMBOL(PrepareTelegramDelegateHeaders)(*linked, session, text(bad[i][0]), text(bad[i][1]),
            text(bad[i][2]), text(bad[i][3]), bytes(proof, sizeof proof), bytes(credential, sizeof credential)) == AuthResult_AUTH_PAYLOAD_FAILED);
        assert(!proof[0] && !credential[0]);
    }
    if (stars) {
        expected_telegram_request = &telegram_cases[2];
        assert(MESH_ASYNC_DELEGATED_SYMBOL(BeginTelegramDelegateRequest)(&pending, *linked, session, transport,
            TelegramDelegateOperation_Balance, text(""), text(""), bytes(output, sizeof output)));
        int previous_cancels = cancels;
        MESH_ASYNC_DELEGATED_SYMBOL(CancelDelegate)(&pending);
        MESH_ASYNC_DELEGATED_SYMBOL(CancelDelegate)(&pending);
        assert(!active && cancels == previous_cancels + 1 && pending.result == AuthResult_AUTH_REQUEST_FAILED);
        failed_transport = true;
        assert(MESH_ASYNC_DELEGATED_SYMBOL(BeginTelegramDelegateRequest)(&pending, *linked, session, transport,
            TelegramDelegateOperation_Balance, text(""), text(""), bytes(output, sizeof output)));
        assert(!MESH_ASYNC_DELEGATED_SYMBOL(PollDelegate)(&pending));
        assert(MESH_ASYNC_DELEGATED_SYMBOL(PollDelegate)(&pending) && pending.result == AuthResult_AUTH_REQUEST_FAILED);
        failed_transport = false;
        response_status = 403;
        assert(MESH_ASYNC_DELEGATED_SYMBOL(BeginTelegramDelegateRequest)(&pending, *linked, session, transport,
            TelegramDelegateOperation_Balance, text(""), text(""), bytes(output, sizeof output)));
        assert(!MESH_ASYNC_DELEGATED_SYMBOL(PollDelegate)(&pending));
        assert(MESH_ASYNC_DELEGATED_SYMBOL(PollDelegate)(&pending));
        assert(pending.status == 403 && pending.result == AuthResult_AUTH_FAILED && !session->session_id[0]);
    }
    expected_telegram_request = NULL;
}

static void check_telegram_binding(String document)
{
    AccountKeys owner;
    assert(CreateAccountKeys(&owner));
    GrantScope scopes[16];
    Grant grant = {0};
    assert(MESH_AUTHORIZATION_SYMBOL(ViewGrant)(&original, bytes(scopes, 16), &grant));
    grant.account_id = text((char *)owner.public_id);
    grant.bot_id = 123456;
    grant.telegram_id = 1234;
    char message[8192], signature[4841], grant_json[12000], telegram_answer[18000];
    assert(MESH_AUTHORIZATION_SYMBOL(BuildGrantMessage)(grant, bytes(message, sizeof message)));
    assert(SignAccountMessage(&owner, text(message), bytes(signature, sizeof signature)));
    grant.signature = text(signature);
    assert(MESH_AUTHORIZATION_SYMBOL(BuildGrantBody)(grant, bytes(grant_json, sizeof grant_json)));
    String credential = object(object(document, "answer"), "credential");
    int count = snprintf(telegram_answer, sizeof telegram_answer,
        "{\"credential\":%.*s,\"grant\":%s,\"owner_public_key\":\"%s\"}",
        (int)credential.length, credential.data, grant_json, owner.public_key_hex);
    assert(count > 0 && count < (int)sizeof telegram_answer);
    DelegateClient telegram = client;
    telegram.account_id = grant.account_id;
    telegram.bot_id = grant.bot_id;
    telegram.telegram_id = grant.telegram_id;
    DelegateSession session;
    assert(MESH_DELEGATED_SYMBOL(AcceptSessionAnswer)(telegram, 200, text(telegram_answer), 1,
        &session) == AuthResult_AUTH_OK);
    assert(!telegram.grant->telegram_stars);
    check_telegram_async(&telegram, &session, false);

    char explicit_false[18000];
    count = snprintf(explicit_false, sizeof explicit_false,
        "{\"credential\":%.*s,\"grant\":%.*s,\"telegram_stars\":false},\"owner_public_key\":\"%s\"}",
        (int)credential.length, credential.data, (int)strlen(grant_json) - 1, grant_json, owner.public_key_hex);
    assert(count > 0 && count < (int)sizeof explicit_false);
    assert(MESH_DELEGATED_SYMBOL(AcceptSessionAnswer)(telegram, 200, text(explicit_false), 1,
        &session) == AuthResult_AUTH_OK && !telegram.grant->telegram_stars);

    grant.telegram_stars = true;
    char extended_message[8192];
    assert(MESH_AUTHORIZATION_SYMBOL(BuildGrantMessage)(grant, bytes(extended_message, sizeof extended_message)));
    assert(strncmp(message, extended_message, strlen(message)) == 0);
    assert(strcmp(extended_message + strlen(message), "telegram-stars-purchases\n") == 0);
    assert(!MESH_AUTHORIZATION_SYMBOL(VerifyGrantSignature)(grant, text((char *)owner.public_key_hex), clock_now));
    Client approval = {.app_id = grant.app_id, .identity = {.account_id = grant.account_id, .signing_context = &owner},
        .signer = SignAccountMessage};
    assert(MESH_AUTHORIZATION_OWNER_SYMBOL(PrepareGrantApproval)(approval, grant, bytes(grant_json, sizeof grant_json)) == AuthResult_AUTH_OK);
    assert(strstr(grant_json, "\"telegram_stars\":true"));
    count = snprintf(telegram_answer, sizeof telegram_answer,
        "{\"credential\":%.*s,\"grant\":%s,\"owner_public_key\":\"%s\"}",
        (int)credential.length, credential.data, grant_json, owner.public_key_hex);
    assert(count > 0 && count < (int)sizeof telegram_answer);
    char edited_answer[18000];
    strcpy(edited_answer, telegram_answer);
    char *modified_flag = strstr(edited_answer, "\"telegram_stars\":true");
    assert(modified_flag);
    memcpy(strchr(modified_flag, ':') + 1, "null", 4);
    assert(MESH_DELEGATED_SYMBOL(AcceptSessionAnswer)(telegram, 200, text(edited_answer), 1,
        &session) == AuthResult_AUTH_PAYLOAD_FAILED);
    memcpy(strchr(modified_flag, ':') + 1, "0   ", 4);
    assert(MESH_DELEGATED_SYMBOL(AcceptSessionAnswer)(telegram, 200, text(edited_answer), 1,
        &session) == AuthResult_AUTH_PAYLOAD_FAILED);
    memcpy(strchr(modified_flag, ':') + 1, "true", 4);
    char *next_field = strchr(strchr(modified_flag, ':') + 1, ',');
    const char duplicate[] = ",\"telegram_\\u0073tars\":false";
    memmove(next_field + sizeof duplicate - 1, next_field, strlen(next_field) + 1);
    memcpy(next_field, duplicate, sizeof duplicate - 1);
    assert(MESH_DELEGATED_SYMBOL(AcceptSessionAnswer)(telegram, 200, text(edited_answer), 1,
        &session) == AuthResult_AUTH_PAYLOAD_FAILED);
    assert(MESH_DELEGATED_SYMBOL(AcceptSessionAnswer)(telegram, 200, text(telegram_answer), 1,
        &session) == AuthResult_AUTH_OK);
    assert(telegram.grant->telegram_stars);
    check_telegram_async(&telegram, &session, true);

    strcpy(answer, telegram_answer);
    char output[18000];
    PendingDelegate pending = {0};
    AsyncTransport transport = {.context = &telegram, .start = {.call = start_telegram_async},
        .poll = {.call = poll_async}, .cancel = {.call = cancel_async}};
    expected_telegram_request = &telegram_cases[2];
    response_status = 200;
    int before = transfers;
    assert(!session.session_id[0]);
    assert(MESH_ASYNC_DELEGATED_SYMBOL(BeginTelegramDelegateRequest)(&pending, telegram, &session, transport,
        TelegramDelegateOperation_Balance, text(""), text(""), bytes(output, sizeof output)));
    for (int i = 0; i < 9 && !pending.done; i++) {
        MESH_ASYNC_DELEGATED_SYMBOL(PollDelegate)(&pending);
    }
    assert(pending.done && pending.result == AuthResult_AUTH_OK && transfers == before + 3);
    expected_telegram_request = NULL;

    int64_t previous_clock = clock_now;
    clock_now = telegram.grant->expires_at;
    assert(!MESH_DELEGATED_SYMBOL(DelegateTelegramStarsAllowed)(telegram));
    clock_now = previous_clock;
    telegram.bot_id = 123457;
    assert(MESH_DELEGATED_SYMBOL(AcceptSessionAnswer)(telegram, 200, text(telegram_answer), 1,
        &session) == AuthResult_AUTH_FAILED);
    telegram.bot_id = 123456;
    telegram.telegram_id = 1235;
    assert(MESH_DELEGATED_SYMBOL(AcceptSessionAnswer)(telegram, 200, text(telegram_answer), 1,
        &session) == AuthResult_AUTH_FAILED);
    telegram.bot_id = 0;
    telegram.telegram_id = 0;
    assert(MESH_DELEGATED_SYMBOL(AcceptSessionAnswer)(telegram, 200, text(telegram_answer), 1,
        &session) == AuthResult_AUTH_FAILED);
    telegram.bot_id = 123456;
    assert(!MESH_DELEGATED_SYMBOL(DelegateClientValid)(telegram));
    SecureWipe(owner.private_key_hex, sizeof owner.private_key_hex);
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    FILE *file = fopen(argv[1], "rb");
    assert(file);
    size_t count = fread(fixture, 1, sizeof fixture - 1, file);
    assert(!ferror(file) && feof(file));
    fclose(file);
    fixture[count] = 0;
    String document = text(fixture);
    configure(document);
    check_messages(document);
    check_acceptance();
    check_envelopes();
    check_transports();
    check_advancing_clock();
    check_telegram_binding(document);
    puts("Mesh delegated fixtures, ownership, scopes, envelopes and async transports passed");
    return 0;
}
