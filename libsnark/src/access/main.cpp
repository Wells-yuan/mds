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
boost::optional<r1cs_gg_ppzksnark_proof<ppzksnark_ppT>> generate_access_proof(r1cs_gg_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                                    uint256 id,
                                                                    uint256 cmtU,
                                                                    uint256 token,
                                                                    uint256 pk,
                                                                    uint256 ek,
                                                                    uint256 r,
                                                                    uint256 rt
                                                                   )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;  // 定义原始模型，该模型包含constraint_system成员变量
    access_gadget<FieldT> g(pb); // 构造新模型
    g.generate_r1cs_constraints(); // 生成约束

    g.generate_r1cs_witness(id, cmtU, token, pk, ek, r, rt); // 为新模型的参数生成证明

    cout << "pb.is_satisfied() is " << pb.is_satisfied() << endl;

    if (!pb.is_satisfied()) { // 三元组R1CS是否满足  < A , X > * < B , X > = < C , X >
        return boost::none;
    }

    // 调用libsnark库中生成proof的函数
    return r1cs_gg_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

// 验证proof
template<typename ppzksnark_ppT>
bool verify_access_proof(r1cs_gg_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                    r1cs_gg_ppzksnark_proof<ppzksnark_ppT> proof,
                    const uint256& id,
                    const uint256& cmtU,
                    const uint256& token
                  )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    const r1cs_primary_input<FieldT> input = access_gadget<FieldT>::witness_map(
        id,
        cmtU,
        token
    ); 

    // 调用libsnark库中验证proof的函数
    return r1cs_gg_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}


template<typename ppzksnark_ppT>
r1cs_gg_ppzksnark_keypair<ppzksnark_ppT> Setup() {
    default_r1cs_gg_ppzksnark_pp::init_public_params();
    
    typedef libff::Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;

    access_gadget<FieldT> access(pb);
    access.generate_r1cs_constraints();// 生成约束

    // check conatraints
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    std::cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    
    // key pair generation
    r1cs_gg_ppzksnark_keypair<ppzksnark_ppT> keypair = r1cs_gg_ppzksnark_generator<ppzksnark_ppT>(constraint_system);

    return keypair;
}

template<typename ppzksnark_ppT> //--Agzs
bool test_access_gadget_with_instance(r1cs_gg_ppzksnark_keypair<ppzksnark_ppT> keypair)
{
    uint256 id = uint256S("11111Abcd");
    uint256 pk = uint256S("09cd53");
    uint256 ek = uint256S("5bc089a4a");
    uint256 r = uint256S("1234dfa9256");
    uint256 rt = uint256S("1234cab56");

    CSHA256 hasher;
    uint256 cmtU;
    hasher.Write(id.begin(), 32);
    hasher.Write(pk.begin(), 32);
    hasher.Write(ek.begin(), 32);
    hasher.Write(r.begin(), 32);
    hasher.Finalize(cmtU.begin());

    uint256 token = Compute_PRF(pk, rt);

    // 生成proof
    cout << "Trying to generate proof..." << endl;

    struct timeval gen_start, gen_end;
    double accessTimeUse;
    gettimeofday(&gen_start,NULL);

    auto proof = generate_access_proof<default_r1cs_gg_ppzksnark_pp>(keypair.pk, 
                                                            id,
                                                            cmtU,
                                                            token,
                                                            pk,
                                                            ek,
                                                            r,
                                                            rt);

    gettimeofday(&gen_end, NULL);
    accessTimeUse = gen_end.tv_sec - gen_start.tv_sec + (gen_end.tv_usec - gen_start.tv_usec)/1000000.0;
    printf("\n\nGen Access Proof Use Time:%fs\n\n", accessTimeUse);

    // verify proof
    if (!proof) {
        printf("generate access proof fail!!!\n");
        return false;
    } else {
        struct timeval ver_start, ver_end;
        double accessVerTimeUse;
        gettimeofday(&ver_start, NULL);

        bool result = verify_access_proof(keypair.vk, 
                                   *proof, 
                                   id,
                                   cmtU,
                                   token
                                   );

        gettimeofday(&ver_end, NULL);
        accessVerTimeUse = ver_end.tv_sec - ver_start.tv_sec + (ver_end.tv_usec - ver_start.tv_usec)/1000000.0;
        printf("\n\nVer Access Proof Use Time:%fs\n\n", accessVerTimeUse);
         
        if (!result){
            cout << "Verifying access proof unsuccessfully!!!" << endl;
        } else {
            cout << "Verifying access proof successfully!!!" << endl;
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
    printf("\n\nAccess Setup Time Usage:%fs\n\n",timeuse);

    libff::print_header("#             testing access gadget");

    test_access_gadget_with_instance<default_r1cs_gg_ppzksnark_pp>(keypair);

    return 0;
}

