#include <stdio.h>
#include <iostream>

#include<sys/time.h>

#include <boost/optional.hpp>
#include <boost/foreach.hpp>
#include <boost/format.hpp>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp"
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp"

#include "deps/sha256.h"
#include "uint256.h"
#include "util.h"

#include "producecgo.hpp"

using namespace libsnark;
using namespace libff;
using namespace std;

#include "circuit/gadget.tcc"

int convertFromAscii(uint8_t ch)
{
    if (ch >= '0' && ch <= '9')
    {
        return ch - '0';
    }
    else if (ch >= 'a' && ch <= 'f')
    {
        return ch - 'a' + 10;
    }
}

libff::bigint<libff::alt_bn128_r_limbs> libsnarkBigintFromBytes(const uint8_t *_x)
{
    libff::bigint<libff::alt_bn128_r_limbs> x;

    for (unsigned i = 0; i < 4; i++)
    {
        for (unsigned j = 0; j < 8; j++)
        {
            x.data[3 - i] |= uint64_t(_x[i * 8 + j]) << (8 * (7 - j));
        }
    }
    return x;
}

template <typename T>
void writeToFile(std::string path, T &obj)
{
    std::stringstream ss;
    ss << obj;
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template <typename T>
T loadFromFile(std::string path)
{
    std::stringstream ss;
    std::ifstream fh(path, std::ios::binary);

    assert(fh.is_open());

    ss << fh.rdbuf();
    fh.close();

    ss.rdbuf()->pubseekpos(0, std::ios_base::in);

    T obj;
    ss >> obj;

    return obj;
}

void serializeProvingKeyToFile(r1cs_gg_ppzksnark_proving_key<alt_bn128_pp> pk, const char *pk_path)
{
    writeToFile(pk_path, pk);
}

void vkToFile(r1cs_gg_ppzksnark_verification_key<alt_bn128_pp> vk, const char *vk_path)
{
    writeToFile(vk_path, vk);
}

void proofToFile(r1cs_gg_ppzksnark_proof<alt_bn128_pp> pro, const char *pro_path)
{
    writeToFile(pro_path, pro);
}

r1cs_gg_ppzksnark_proving_key<alt_bn128_pp> deserializeProvingKeyFromFile(const char *pk_path)
{
    return loadFromFile<r1cs_gg_ppzksnark_proving_key<alt_bn128_pp>>(pk_path);
}

r1cs_gg_ppzksnark_verification_key<alt_bn128_pp> deserializevkFromFile(const char *vk_path)
{
    return loadFromFile<r1cs_gg_ppzksnark_verification_key<alt_bn128_pp>>(vk_path);
}

r1cs_gg_ppzksnark_proof<alt_bn128_pp> deserializeproofFromFile(const char *pro_path)
{
    return loadFromFile<r1cs_gg_ppzksnark_proof<alt_bn128_pp>>(pro_path);
}

std::string HexStringFromLibsnarkBigint(libff::bigint<libff::alt_bn128_r_limbs> _x)
{
    uint8_t x[32];
    for (unsigned i = 0; i < 4; i++)
        for (unsigned j = 0; j < 8; j++)
            x[i * 8 + j] = uint8_t(uint64_t(_x.data[3 - i]) >> (8 * (7 - j)));

    std::stringstream ss;
    ss << std::setfill('0');
    for (unsigned i = 0; i < 32; i++)
    {
        ss << std::hex << std::setw(2) << (int)x[i];
    }

    std::string str = ss.str();
    return str.erase(0, min(str.find_first_not_of('0'), str.size() - 1));
}

std::string outputPointG1AffineAsHex(libff::alt_bn128_G1 _p)
{
    libff::alt_bn128_G1 aff = _p;
    aff.to_affine_coordinates();

    std::string s_x = HexStringFromLibsnarkBigint(aff.X.as_bigint());
    while (s_x.size() < 64)
    {
        s_x = "0" + s_x;
    }

    std::string s_y = HexStringFromLibsnarkBigint(aff.Y.as_bigint());
    while (s_y.size() < 64)
    {
        s_y = "0" + s_y;
    }
    return s_x + s_y;
}

std::string outputPointG2AffineAsHex(libff::alt_bn128_G2 _p)
{
    libff::alt_bn128_G2 aff = _p;
    aff.to_affine_coordinates();

    std::string x_1 = HexStringFromLibsnarkBigint(aff.X.c1.as_bigint());
    while (x_1.size() < 64)
    {
        x_1 = "0" + x_1;
    }
    std::string x_0 = HexStringFromLibsnarkBigint(aff.X.c0.as_bigint());
    while (x_0.size() < 64)
    {
        x_0 = "0" + x_0;
    }
    std::string y_1 = HexStringFromLibsnarkBigint(aff.Y.c1.as_bigint());
    while (y_1.size() < 64)
    {
        y_1 = "0" + y_1;
    }
    std::string y_0 = HexStringFromLibsnarkBigint(aff.Y.c0.as_bigint());
    while (y_0.size() < 64)
    {
        y_0 = "0" + y_0;
    }
    return x_1 + x_0 + y_1 + y_0;
}
std::string string_proof_as_hex(libsnark::r1cs_gg_ppzksnark_proof<libff::alt_bn128_pp> proof)
{
    std::string A = outputPointG1AffineAsHex(proof.g_A);

    std::string B = outputPointG2AffineAsHex(proof.g_B);

    std::string C = outputPointG1AffineAsHex(proof.g_C);

    std::string proof_string = A + B + C;

    return proof_string;
}

template <typename ppzksnark_ppT>
r1cs_gg_ppzksnark_proof<ppzksnark_ppT> generate_produce_proof(r1cs_gg_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                        uint256 id,
                                                        uint256 role,
                                                        uint256 cmtA,
                                                        uint256 cmtU,
                                                        uint256 henc,
                                                        uint256 auth,
                                                        uint256 pk,
                                                        uint256 sk,
                                                        uint256 ek,
                                                        uint256 r
                                                        )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;         // 定义原始模型，该模型包含constraint_system成员变量
    produce_gadget<FieldT> g(pb);     // 构造新模型
    g.generate_r1cs_constraints(); // 生成约束

    g.generate_r1cs_witness(id, role, cmtA, cmtU, henc, auth, pk, sk, ek, r); // 为新模型的参数生成证明

    if (!pb.is_satisfied())
    { // 三元组R1CS是否满足  < A , X > * < B , X > = < C , X >
        cout << "can not generate produce proof" << endl;
        return r1cs_gg_ppzksnark_proof<ppzksnark_ppT>();
    }

    // 调用libsnark库中生成proof的函数
    return r1cs_gg_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

// 验证proof
template <typename ppzksnark_ppT>
bool verify_produce_proof(r1cs_gg_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                  r1cs_gg_ppzksnark_proof<ppzksnark_ppT> proof,
                  uint256& id,
                  uint256& role,
                  uint256& cmtA,
                  uint256& cmtU,
                  uint256& henc,
                  uint256& auth)
{
    typedef Fr<ppzksnark_ppT> FieldT;

    const r1cs_primary_input<FieldT> input = produce_gadget<FieldT>::witness_map(
        id,
        role,
        cmtA,
        cmtU,
        henc,
        auth);

    // 调用libsnark库中验证proof的函数
    return r1cs_gg_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}

//func GenCMT(value uint64, sn []byte, r []byte)
char *genCMTA(char *id_string, char *role_string, char *pk_string, char *ek_string, char *r_string)
{
    uint256 id = uint256S(id_string);
    uint256 role = uint256S(role_string);
    uint256 pk = uint256S(pk_string);
    uint256 ek = uint256S(ek_string);
    uint256 r = uint256S(r_string);

    CSHA256 hasher;
    hasher.Write(id.begin(), 32);
    hasher.Write(role.begin(), 32);
    hasher.Write(pk.begin(), 32);
    hasher.Write(ek.begin(), 32);
    hasher.Write(r.begin(), 32);

    uint256 cmtA;
    hasher.Finalize(cmtA.begin());
    std::string cmtA_c = cmtA.ToString();

    char *p = new char[65]; //必须使用new开辟空间 不然cgo调用该函数结束全为0
    cmtA_c.copy(p, 64, 0);
    *(p + 64) = '\0'; //手动加结束符

    return p;
}

char *genCMTU(char *id_string, char *pk_string, char *ek_string, char *r_string)
{
    uint256 id = uint256S(id_string);
    uint256 pk = uint256S(pk_string);
    uint256 ek = uint256S(ek_string);
    uint256 r = uint256S(r_string);

    CSHA256 hasher;
    hasher.Write(id.begin(), 32);
    hasher.Write(pk.begin(), 32);
    hasher.Write(ek.begin(), 32);
    hasher.Write(r.begin(), 32);

    uint256 cmtU;
    hasher.Finalize(cmtU.begin());
    std::string cmtU_c = cmtU.ToString();

    char *p = new char[65]; //必须使用new开辟空间 不然cgo调用该函数结束全为0
    cmtU_c.copy(p, 64, 0);
    *(p + 64) = '\0'; //手动加结束符

    return p;
}

char* computePRF(char* sk_string, char* r_string)
{
    uint256 sk = uint256S(sk_string);
    uint256 r = uint256S(r_string);
    uint256 sn = Compute_PRF(sk, r);
    std::string sn_c = sn.ToString();

    char *p = new char[65]; //必须使用new开辟空间 不然cgo调用该函数结束全为0
    sn_c.copy(p, 64, 0);
    *(p + 64) = '\0'; //手动加结束符

    return p;
}

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
                   )
{
    //从字符串转uint256
    uint256 id = uint256S(id_string);
    uint256 role = uint256S(role_string);
    uint256 cmtA = uint256S(cmtA_string);
    uint256 cmtU = uint256S(cmtU_string);
    uint256 henc = uint256S(henc_string);
    uint256 auth = uint256S(auth_string);
    uint256 pk = uint256S(pk_string);
    uint256 sk = uint256S(sk_string);
    uint256 ek = uint256S(ek_string);
    uint256 r = uint256S(r_string);

    //初始化参数
    alt_bn128_pp::init_public_params();
    
    struct timeval t1, t2;
    double timeuse;
    gettimeofday(&t1,NULL);

    r1cs_gg_ppzksnark_keypair<alt_bn128_pp> keypair;
    //cout << "Trying to read produce proving key file..." << endl;
    //cout << "Please be patient as this may take about 20 seconds. " << endl;
    keypair.pk = deserializeProvingKeyFromFile("/usr/local/prfKey/producepk.raw");

    gettimeofday(&t2,NULL);
    timeuse = t2.tv_sec - t1.tv_sec + (t2.tv_usec - t1.tv_usec)/1000000.0;
    // printf("\n\n reading produce pk Use Time:%fs\n\n",timeuse);

    // 生成proof
    // cout << "Trying to generate produce proof..." << endl;

    libsnark::r1cs_gg_ppzksnark_proof<libff::alt_bn128_pp> proof = generate_produce_proof<alt_bn128_pp>(keypair.pk, id, role, cmtA, cmtU, henc, auth, pk, sk, ek, r);

    //proof转字符串
    std::string proof_string = string_proof_as_hex(proof);

    // char *p = new char[1153];
    // proof_string.copy(p, 1152, 0);
    // *(p + 1152) = '\0';
    char *p = new char[513];
    proof_string.copy(p, 512, 0);
    *(p + 512) = '\0';

    return p;
}

bool verifyProduceproof(
    char *data, 
    char *id_string, 
    char *role_string, 
    char *cmtA_string, 
    char *cmtU_string, 
    char *henc_string, 
    char *auth_string)
{
    uint256 id = uint256S(id_string);
    uint256 role = uint256S(role_string);
    uint256 cmtA = uint256S(cmtA_string);
    uint256 cmtU = uint256S(cmtU_string);
    uint256 henc = uint256S(henc_string);
    uint256 auth = uint256S(auth_string);

    alt_bn128_pp::init_public_params();
    
    struct timeval t1, t2;
    double timeuse;
    gettimeofday(&t1,NULL);

    r1cs_gg_ppzksnark_keypair<alt_bn128_pp> keypair;
    keypair.vk = deserializevkFromFile("/usr/local/prfKey/producevk.raw");

    gettimeofday(&t2,NULL);
    timeuse = t2.tv_sec - t1.tv_sec + (t2.tv_usec - t1.tv_usec)/1000000.0;
    // printf("\n\n reading produce vk Use Time:%fs\n\n",timeuse);

    libsnark::r1cs_gg_ppzksnark_proof<libff::alt_bn128_pp> proof;

    uint8_t A_x[64];
    uint8_t A_y[64];

    uint8_t B_x_1[64];
    uint8_t B_x_0[64];
    uint8_t B_y_1[64];
    uint8_t B_y_0[64];

    uint8_t C_x[64];
    uint8_t C_y[64];

    for (int i = 0; i < 64; i++)
    {
        A_x[i] = uint8_t(data[i + 0]);
        A_y[i] = uint8_t(data[i + 64]);

        B_x_1[i] = uint8_t(data[i + 128]);
        B_x_0[i] = uint8_t(data[i + 192]);
        B_y_1[i] = uint8_t(data[i + 256]);
        B_y_0[i] = uint8_t(data[i + 320]);

        C_x[i] = uint8_t(data[i + 384]);
        C_y[i] = uint8_t(data[i + 448]);
    }

    for (int i = 0, j = 0; i < 64; i += 2, j++)
    {
        A_x[j] = uint8_t(convertFromAscii(A_x[i]) * 16 + convertFromAscii(A_x[i + 1]));
        A_y[j] = uint8_t(convertFromAscii(A_y[i]) * 16 + convertFromAscii(A_y[i + 1]));

        B_x_1[j] = uint8_t(convertFromAscii(B_x_1[i]) * 16 + convertFromAscii(B_x_1[i + 1]));
        B_x_0[j] = uint8_t(convertFromAscii(B_x_0[i]) * 16 + convertFromAscii(B_x_0[i + 1]));
        B_y_1[j] = uint8_t(convertFromAscii(B_y_1[i]) * 16 + convertFromAscii(B_y_1[i + 1]));
        B_y_0[j] = uint8_t(convertFromAscii(B_y_0[i]) * 16 + convertFromAscii(B_y_0[i + 1]));

        C_x[j] = uint8_t(convertFromAscii(C_x[i]) * 16 + convertFromAscii(C_x[i + 1]));
        C_y[j] = uint8_t(convertFromAscii(C_y[i]) * 16 + convertFromAscii(C_y[i + 1]));
    }

    libff::bigint<libff::alt_bn128_r_limbs> a_x = libsnarkBigintFromBytes(A_x);
    libff::bigint<libff::alt_bn128_r_limbs> a_y = libsnarkBigintFromBytes(A_y);

    libff::bigint<libff::alt_bn128_r_limbs> b_x_1 = libsnarkBigintFromBytes(B_x_1);
    libff::bigint<libff::alt_bn128_r_limbs> b_x_0 = libsnarkBigintFromBytes(B_x_0);
    libff::bigint<libff::alt_bn128_r_limbs> b_y_1 = libsnarkBigintFromBytes(B_y_1);
    libff::bigint<libff::alt_bn128_r_limbs> b_y_0= libsnarkBigintFromBytes(B_y_0);

    libff::bigint<libff::alt_bn128_r_limbs> c_x = libsnarkBigintFromBytes(C_x);
    libff::bigint<libff::alt_bn128_r_limbs> c_y = libsnarkBigintFromBytes(C_y);

    //ecc element
    proof.g_A.X = a_x;
    proof.g_A.Y = a_y;
    
    proof.g_B.X.c1 = b_x_1;
    proof.g_B.X.c0 = b_x_0;
    proof.g_B.Y.c1 = b_y_1;
    proof.g_B.Y.c0 = b_y_0;
   
    proof.g_C.X = c_x;
    proof.g_C.Y = c_y;

    bool result = verify_produce_proof(keypair.vk, proof, id, role, cmtA, cmtU, henc, auth);

    if (!result)
    {
        cout << "Verifying produce proof failed" << endl;
    }
    else
    {
        cout << "Verifying produce proof successfully" << endl;
    }

    return result;
}