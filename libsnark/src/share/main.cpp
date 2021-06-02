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
template <typename ppzksnark_ppT>
boost::optional<r1cs_gg_ppzksnark_proof<ppzksnark_ppT>> generate_share_proof(r1cs_gg_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                                    uint256 idA,
                                                                    uint256 idB,
                                                                    uint256 cmtA,
                                                                    uint256 cmtU1,
                                                                    uint256 cmtU2,
                                                                    uint256 henc,
                                                                    uint256 auth,
                                                                    uint256 pkB,
                                                                    uint256 pkC,
                                                                    uint256 sk,
                                                                    uint256 ekA,
                                                                    uint256 ekB,
                                                                    uint256 rA,
                                                                    uint256 rB,
                                                                    uint256 roleA
                                                                   )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;  // 定义原始模型，该模型包含constraint_system成员变量
    share_gadget<FieldT> g(pb); // 构造新模型
    g.generate_r1cs_constraints(); // 生成约束

    g.generate_r1cs_witness(idA, idB, cmtA, cmtU1, cmtU2, henc, auth, pkB, pkC, sk, ekA, ekB, rA, rB, roleA); // 为新模型的参数生成证明

    cout << "pb.is_satisfied() is " << pb.is_satisfied() << endl;

    if (!pb.is_satisfied()) { // 三元组R1CS是否满足  < A , X > * < B , X > = < C , X >
        return boost::none;
    }

    // 调用libsnark库中生成proof的函数
    return r1cs_gg_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

// 验证proof
template <typename ppzksnark_ppT>
bool verify_share_proof(r1cs_gg_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                  r1cs_gg_ppzksnark_proof<ppzksnark_ppT> proof,
                  uint256& idA,
                  uint256& idB,
                  uint256& cmtA,
                  uint256& cmtU1,
                  uint256& cmtU2,
                  uint256& henc,
                  uint256& auth)
{
    typedef Fr<ppzksnark_ppT> FieldT;

    const r1cs_primary_input<FieldT> input = share_gadget<FieldT>::witness_map(
        idA,
        idB,
        cmtA,
        cmtU1,
        cmtU2,
        henc,
        auth);

    // 调用libsnark库中验证proof的函数
    return r1cs_gg_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}

template<typename ppzksnark_ppT>
r1cs_gg_ppzksnark_keypair<ppzksnark_ppT> Setup() {
    default_r1cs_gg_ppzksnark_pp::init_public_params();
    
    typedef libff::Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;

    share_gadget<FieldT> share(pb);
    share.generate_r1cs_constraints();// 生成约束

    // check conatraints
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    std::cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    
    // key pair generation
    r1cs_gg_ppzksnark_keypair<ppzksnark_ppT> keypair = r1cs_gg_ppzksnark_generator<ppzksnark_ppT>(constraint_system);

    return keypair;
}

template<typename ppzksnark_ppT> //--Agzs
bool test_share_gadget_with_instance(r1cs_gg_ppzksnark_keypair<ppzksnark_ppT> keypair)
{
    uint256 idA = uint256S("11111Abcd");
    uint256 idB = uint256S("111432c11Abcd");
    // uint256 wrong_id = uint256S("00000");
    uint256 pkB = uint256S("09cd53");
    uint256 pkC = uint256S("78609cd53");
    uint256 sk = uint256S("9c0a334");
    uint256 rA = uint256S("123456");
    uint256 rB = uint256S("123csa984456");
    uint256 ekA= uint256S("2cb237b");
    uint256 ekB = Compute_PRF(sk, rB);
    uint256 roleA = uint256S("22222Ba");

    CSHA256 hasher;
    uint256 cmtA;
    hasher.Write(idA.begin(), 32);
    hasher.Write(roleA.begin(), 32);
    hasher.Write(pkB.begin(), 32);
    hasher.Write(ekA.begin(), 32);
    hasher.Write(rA.begin(), 32);
    hasher.Finalize(cmtA.begin());
    cout << "cmtA is:" << cmtA.ToString() << endl;

    CSHA256 hasher1;
    uint256 cmtU1;
    hasher1.Write(idB.begin(), 32);
    hasher1.Write(pkB.begin(), 32);
    hasher1.Write(ekB.begin(), 32);
    hasher1.Write(rB.begin(), 32);
    hasher1.Finalize(cmtU1.begin());
    cout << "cmtU1 is:" << cmtU1.ToString() << endl;
    
    CSHA256 hasher2;
    uint256 cmtU2;
    hasher2.Write(idB.begin(), 32);
    hasher2.Write(pkC.begin(), 32);
    hasher2.Write(ekB.begin(), 32);
    hasher2.Write(rB.begin(), 32);
    hasher2.Finalize(cmtU2.begin());
    cout << "cmtU2 is:" << cmtU2.ToString() << endl;

    uint256 aux = uint256S("6543caaf21");
    uint256 henc;
    CSHA256 hasher3;
    hasher3.Write(aux.begin(), 32);
    hasher3.Finalize(henc.begin());

    uint256 auth = Compute_PRF(sk, henc);

    // 生成proof
    cout << "Trying to generate proof..." << endl;

    struct timeval gen_start, gen_end;
    double shareTimeUse;
    gettimeofday(&gen_start,NULL);

    auto proof = generate_share_proof<default_r1cs_gg_ppzksnark_pp>(keypair.pk, 
                                                            idA,
                                                            idB,
                                                            cmtA,
                                                            cmtU1,
                                                            cmtU2,
                                                            henc,
                                                            auth,
                                                            pkB,
                                                            pkC,
                                                            sk,
                                                            ekA,
                                                            ekB,
                                                            rA,
                                                            rB,
                                                            roleA
                                                            );

    gettimeofday(&gen_end, NULL);
    shareTimeUse = gen_end.tv_sec - gen_start.tv_sec + (gen_end.tv_usec - gen_start.tv_usec)/1000000.0;
    printf("\n\nGen Produce Proof Use Time:%fs\n\n", shareTimeUse);

    // verify proof
    if (!proof) {
        printf("generate share proof fail!!!\n");
        return false;
    } else {
        struct timeval ver_start, ver_end;
        double shareVerTimeUse;
        gettimeofday(&ver_start, NULL);

        uint256 wrong_aux = uint256S("654320");
        uint256 wrong_henc;
        CSHA256 wrong_hasher;
        wrong_hasher.Write(wrong_aux.begin(), 32);
        wrong_hasher.Finalize(wrong_henc.begin());
        bool result = verify_share_proof(keypair.vk, 
                                   *proof, 
                                   idA,
                                   idB,
                                   cmtA,
                                   cmtU1,
                                   cmtU2,
                                   henc,
                                   auth
                                   );

        gettimeofday(&ver_end, NULL);
        shareVerTimeUse = ver_end.tv_sec - ver_start.tv_sec + (ver_end.tv_usec - ver_start.tv_usec)/1000000.0;
        printf("\n\nVer Produce Proof Use Time:%fs\n\n", shareVerTimeUse);
        //printf("verify result = %d\n", result);
         
        if (!result){
            cout << "Verifying share proof unsuccessfully!!!" << endl;
        } else {
            cout << "Verifying share proof successfully!!!" << endl;
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

    libff::print_header("#             testing share gadget");

    test_share_gadget_with_instance<default_r1cs_gg_ppzksnark_pp>(keypair);

    // Note. cmake can not compile the assert()  --Agzs
    
    return 0;
}

