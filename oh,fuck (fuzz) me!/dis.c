#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include "./capstone/include/capstone.h"
#include <inttypes.h>



struct platform {
        cs_arch arch;
        cs_mode mode;
};


struct platform platforms[] = {
        {
                CS_ARCH_SYSZ,
                CS_MODE_BIG_ENDIAN
        },
        {
                CS_ARCH_SPARC,
                CS_MODE_BIG_ENDIAN
        }
};



int main() {

        csh handle;
        cs_insn *insn;
        int i;
        size_t count;
        uint8_t buf[128];
        ssize_t read_bytes;

        read_bytes = -1;
        memset(buf, 0, 128);
        read_bytes = read(STDIN_FILENO, buf, 128);

                for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {
                        cs_err err = cs_open(platforms[i].arch, platforms[i].mode, &handle);
                        if (err) {
                                continue;
                        }


                        count = cs_disasm(handle, buf, read_bytes, 0x1000, 0, &insn);
                        cs_free(insn, count);


                        cs_close(&handle);
                }

        return 0;
}

