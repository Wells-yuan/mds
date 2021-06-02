#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>

   // cmtA=(id,role,pk,ek,r)
   char *genCMTA(char *id_string, char *role_string, char *pk_string, char *ek_string, char *r_string);
   char *genCMTU(char *id_string, char *pk_string, char *ek_string, char *r_string);
   char* computePRF(char* sk_string, char* r_string);

   char *genProduceproof(
                   char *id_string,
                   char *role_string,
                   char *cmtA_string,
                   char *cmtU_string,
                   char *henc_string,
                   char *auth_string,
                   char *pk_string,
                   char *sk_string,
                   char *ek_string,
                   char *r_string
                      );

   bool verifyProduceproof(char *data, 
    char *id_string, 
    char *role_string, 
    char *cmtA_string, 
    char *cmtU_string, 
    char *henc_string, 
    char *auth_string);

#ifdef __cplusplus
} // extern "C"
#endif