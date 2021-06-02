#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>

   char *genAccessproof(char *id_string,
                   char *cmtU_string,
                   char *token_string,
                   char *pk_string,
                   char *ek_string,
                   char *r_string,
                   char *rt_string
                      );

   bool verifyAccessproof(char *data, 
    char *id_string, 
    char *cmtU_string, 
    char *token_string);

#ifdef __cplusplus
} // extern "C"
#endif