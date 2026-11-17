#include MESH_RECORD_CODEC_HEADER
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char input[65536], packed[65536], opened[65536];
    memset(input, 'x', sizeof input);
    input[0]='{'; input[sizeof input-1]='}';
    Slice source={.data=input,.length=sizeof input};
    Slice encoded={.data=packed,.length=sizeof packed};
    Slice decoded={.data=opened,.length=sizeof opened};
    int64_t count=MESH_RECORD_CODEC_SYMBOL(PackRecord)(source,encoded);
    assert(count>12 && count<sizeof input/10);
    encoded.length=count;
    assert(MESH_RECORD_CODEC_SYMBOL(RecordIsPacked)(encoded));
    assert(MESH_RECORD_CODEC_SYMBOL(PackedRecordSize)(encoded,sizeof input)==sizeof input);
    assert(MESH_RECORD_CODEC_SYMBOL(UnpackRecord)(encoded,decoded,sizeof input)==sizeof input);
    assert(memcmp(input,opened,sizeof input)==0);
    assert(MESH_RECORD_CODEC_SYMBOL(UnpackRecord)(encoded,decoded,sizeof input-1)==-1);
    decoded.length=sizeof opened-1;
    assert(MESH_RECORD_CODEC_SYMBOL(UnpackRecord)(encoded,decoded,sizeof input)==-1);
    decoded.length=sizeof opened;
    ((unsigned char*)packed)[8]=255; ((unsigned char*)packed)[9]=255;
    ((unsigned char*)packed)[10]=255; ((unsigned char*)packed)[11]=255;
    assert(MESH_RECORD_CODEC_SYMBOL(PackedRecordSize)(encoded,8388608)==-1);
    source.length=sizeof input;
    count=MESH_RECORD_CODEC_SYMBOL(PackRecord)(source,(Slice){.data=packed,.length=sizeof packed});
    encoded.length=count;
    packed[count-1]^=1;
    assert(MESH_RECORD_CODEC_SYMBOL(UnpackRecord)(encoded,decoded,sizeof input)==-1);
    source.length=2;
    assert(MESH_RECORD_CODEC_SYMBOL(PackRecord)(source,(Slice){.data=packed,.length=sizeof packed})==0);
    memset(input,'x',sizeof input);
    assert(MESH_RECORD_CODEC_SYMBOL(PackRecord)(source,(Slice){.data=packed,.length=sizeof packed})==0);
    puts("Packed records: bounded gzip, independent buffers, framing and corruption rejection passed");
    return 0;
}
