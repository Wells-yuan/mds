#include <stdio.h>
#include <iostream>

#include <boost/optional.hpp>
#include <boost/foreach.hpp>
#include <boost/format.hpp>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp"
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

#include<sys/time.h>

#include "deps/sha256.h"
#include "uint256.h"
#include "util.h"

using namespace libsnark;
using namespace libff;
using namespace std;

#include "circuit/gadget.tcc"

#define DEBUG 0

// 生成proof
template<typename ppzksnark_ppT>
boost::optional<r1cs_gg_ppzksnark_proof<ppzksnark_ppT>> generate_produce_proof(r1cs_gg_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
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

    protoboard<FieldT> pb;  // 定义原始模型，该模型包含constraint_system成员变量
    produce_gadget<FieldT> g(pb); // 构造新模型
    g.generate_r1cs_constraints(); // 生成约束

    g.generate_r1cs_witness(id, role, cmtA, cmtU, henc, auth, pk, sk, ek, r); // 为新模型的参数生成证明

    cout << "pb.is_satisfied() is " << pb.is_satisfied() << endl;

    if (!pb.is_satisfied()) { // 三元组R1CS是否满足  < A , X > * < B , X > = < C , X >
        return boost::none;
    }

    // 调用libsnark库中生成proof的函数
    return r1cs_gg_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

// 验证proof
template<typename ppzksnark_ppT>
bool verify_produce_proof(r1cs_gg_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                    r1cs_gg_ppzksnark_proof<ppzksnark_ppT> proof,
                    const uint256& id,
                    const uint256& role,
                    const uint256& cmtA,
                    const uint256& cmtU,
                    const uint256& henc,
                    const uint256& auth
                  )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    const r1cs_primary_input<FieldT> input = produce_gadget<FieldT>::witness_map(
        id,
        role,
        cmtA,
        cmtU,
        henc,
        auth
    ); 

    // 调用libsnark库中验证proof的函数
    return r1cs_gg_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}

template<typename ppzksnark_ppT>
void PrintProof(r1cs_gg_ppzksnark_proof<ppzksnark_ppT> proof)
{
    printf("================== Print proof ==================================\n");
    //printf("proof is %x\n", *proof);
    std::cout << "produce proof:\n";

    std::cout << "\n knowledge_commitment<G1<ppT>, G1<ppT> > g_A: ";
    std::cout << "\n   knowledge_commitment.g: \n     " << proof.g_A.g;
    std::cout << "\n   knowledge_commitment.h: \n     " << proof.g_A.h << endl;

    std::cout << "\n knowledge_commitment<G2<ppT>, G1<ppT> > g_B: ";
    std::cout << "\n   knowledge_commitment.g: \n     " << proof.g_B.g;
    std::cout << "\n   knowledge_commitment.h: \n     " << proof.g_B.h << endl;

    std::cout << "\n knowledge_commitment<G1<ppT>, G1<ppT> > g_C: ";
    std::cout << "\n   knowledge_commitment.g: \n     " << proof.g_C.g;
    std::cout << "\n   knowledge_commitment.h: \n     " << proof.g_C.h << endl;


    std::cout << "\n G1<ppT> g_H: " << proof.g_H << endl;
    std::cout << "\n G1<ppT> g_K: " << proof.g_K << endl;
    printf("=================================================================\n");
}

template<typename ppzksnark_ppT>
r1cs_gg_ppzksnark_keypair<ppzksnark_ppT> Setup() {
    default_r1cs_gg_ppzksnark_pp::init_public_params();
    
    typedef libff::Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;

    produce_gadget<FieldT> produce(pb);
    produce.generate_r1cs_constraints();// 生成约束

    // check conatraints
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    std::cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    
    // key pair generation
    r1cs_gg_ppzksnark_keypair<ppzksnark_ppT> keypair = r1cs_gg_ppzksnark_generator<ppzksnark_ppT>(constraint_system);

    return keypair;
}

template<typename ppzksnark_ppT> //--Agzs
bool test_produce_gadget_with_instance(r1cs_gg_ppzksnark_keypair<ppzksnark_ppT> keypair)
{
    uint256 id = uint256S("11111Abcd");
    // uint256 wrong_id = uint256S("00000");
    cout << "id is:" << id.ToString() << endl;
    uint256 role = uint256S("22222Ba");
    cout << "role is:" << role.ToString() << endl;
    uint256 pk = uint256S("09cd53");
    cout << "pk is:" << pk.ToString() << endl;

    uint256 sk = uint256S("9c0a334");//random_uint256();
    cout << "sk is:" << sk.ToString() << endl;
    uint256 r = uint256S("123456");//random_uint256();
    cout << "r is:" << r.ToString() << endl;
    uint256 ek = Compute_PRF(sk, r);//random_uint256();
    cout << "ek is:" << ek.ToString() << endl;

    CSHA256 hasher;
    uint256 cmtA;
    hasher.Write(id.begin(), 32);
    hasher.Write(role.begin(), 32);
    hasher.Write(pk.begin(), 32);
    hasher.Write(ek.begin(), 32);
    hasher.Write(r.begin(), 32);
    hasher.Finalize(cmtA.begin());
    cout << "cmtA is:" << cmtA.ToString() << endl;

    CSHA256 hasher1;
    uint256 cmtU;
    hasher1.Write(id.begin(), 32);
    hasher1.Write(pk.begin(), 32);
    hasher1.Write(ek.begin(), 32);
    hasher1.Write(r.begin(), 32);
    hasher1.Finalize(cmtU.begin());
    cout << "cmtU is:" << cmtU.ToString() << endl;

    uint256 aux = uint256S("654321");
    cout << "aux is:" << aux.ToString() << endl;
    uint256 henc;
    CSHA256 hasher2;
    hasher2.Write(aux.begin(), 32);
    hasher2.Finalize(henc.begin());
    cout << "henc is:" << henc.ToString() << endl;

    uint256 auth = Compute_PRF(sk, henc);
    cout << "auth is:" << auth.ToString() << endl;

    // 生成proof
    cout << "Trying to generate proof..." << endl;

    struct timeval gen_start, gen_end;
    double produceTimeUse;
    gettimeofday(&gen_start,NULL);

    auto proof = generate_produce_proof<default_r1cs_gg_ppzksnark_pp>(keypair.pk, 
                                                            id,
                                                            role,
                                                            cmtA,
                                                            cmtU,
                                                            henc,
                                                            auth,
                                                            pk,
                                                            sk,
                                                            ek,
                                                            r);

    gettimeofday(&gen_end, NULL);
    produceTimeUse = gen_end.tv_sec - gen_start.tv_sec + (gen_end.tv_usec - gen_start.tv_usec)/1000000.0;
    printf("\n\nGen Produce Proof Use Time:%fs\n\n", produceTimeUse);

    // verify proof
    if (!proof) {
        printf("generate produce proof fail!!!\n");
        return false;
    } else {
        struct timeval ver_start, ver_end;
        double produceVerTimeUse;
        gettimeofday(&ver_start, NULL);

        uint256 wrong_aux = uint256S("654320");
        uint256 wrong_henc;
        CSHA256 wrong_hasher;
        wrong_hasher.Write(wrong_aux.begin(), 32);
        wrong_hasher.Finalize(wrong_henc.begin());
        bool result = verify_produce_proof(keypair.vk, 
                                   *proof, 
                                   id,
                                   role,
                                   cmtA,
                                   cmtU,
                                   henc,
                                   auth
                                   );

        gettimeofday(&ver_end, NULL);
        produceVerTimeUse = ver_end.tv_sec - ver_start.tv_sec + (ver_end.tv_usec - ver_start.tv_usec)/1000000.0;
        printf("\n\nVer Produce Proof Use Time:%fs\n\n", produceVerTimeUse);
        //printf("verify result = %d\n", result);
         
        if (!result){
            cout << "Verifying produce proof unsuccessfully!!!" << endl;
        } else {
            cout << "Verifying produce proof successfully!!!" << endl;
        }
        
        return result;
    }
}

int main () {
    struct timeval t1, t2;
    double timeuse;
    gettimeofday(&t1,NULL);

    //default_r1cs_gg_ppzksnark_pp::init_public_params();
    r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair = Setup<default_r1cs_gg_ppzksnark_pp>();

    gettimeofday(&t2,NULL);
    timeuse = t2.tv_sec - t1.tv_sec + (t2.tv_usec - t1.tv_usec)/1000000.0;
    printf("\n\nProduce Setup Time Usage:%fs\n\n",timeuse);
    //test_r1cs_gg_ppzksnark<dsefault_r1cs_gg_ppzksnark_pp>(1000, 100);
   
    //r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair = Setup<default_r1cs_gg_ppzksnark_pp>();

    libff::print_header("#             testing produce gadget");

    test_produce_gadget_with_instance<default_r1cs_gg_ppzksnark_pp>(keypair);

    // Note. cmake can not compile the assert()  --Agzs
    
    return 0;
}

