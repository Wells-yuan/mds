#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>

   char *genUpdateproof(char *id_string,
                   char *cmtU1_string,
                   char *cmtU2_string,
                   char *henc_string,
                   char *auth_string,
                   char *pkB_string,
                   char *pkD_string,
                   char *sk_string,
                   char *ek_string,
                   char *r_string
                      );

   bool verifyUpdateproof(char *data, 
    char *id_string, 
    char *cmtU1_string, 
    char *cmtU2_string, 
    char *henc_string, 
    char *auth_string);

#ifdef __cplusplus
} // extern "C"
#endif