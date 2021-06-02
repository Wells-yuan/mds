#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>

   // cmtA=(id,role,pk,ek,r)
   // char *genCMTA(char *id_string, char *role_string, char *pk_string, char *ek_string, char *r_string);
   // char *genCMTU(char *id_string, char *pk_string, char *ek_string, char *r_string);
   // char *computePRF(char* sk_string, char* r_string);

   char *genShareproof(
      char *idA_string,
      char *idB_string,
      char *cmtA_string,
      char *cmtU1_string,
      char *cmtU2_string,
      char *henc_string,
      char *auth_string,
      char *pkB_string,
      char *pkC_string,
      char *sk_string,
      char *ekA_string,
      char *ekB_string,
      char *rA_string,
      char *rB_string,
      char *roleA_string);

   bool verifyShareproof(
      char *data,
      char *idA_string, 
      char *idB_string, 
      char *cmtA_string,
      char *cmtU1_string, 
      char *cmtU2_string, 
      char *henc_string, 
      char *auth_string);

#ifdef __cplusplus
} // extern "C"
#endif