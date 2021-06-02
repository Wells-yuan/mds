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
boost::optional<r1cs_gg_ppzksnark_proof<ppzksnark_ppT>> generate_update_proof(r1cs_gg_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                        uint256 id,
                                                        uint256 cmtU1,
                                                        uint256 cmtU2,
                                                        uint256 henc,
                                                        uint256 auth,
                                                        uint256 pkB,
                                                        uint256 pkD,
                                                        uint256 sk,
                                                        uint256 ek,
                                                        uint256 r
                                                        )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;
    update_gadget<FieldT> g(pb);     // 构造新模型
    g.generate_r1cs_constraints(); // 生成约束

    g.generate_r1cs_witness(id, cmtU1, cmtU2, henc, auth, pkB, pkD, sk, ek, r); // 为新模型的参数生成证明

    if (!pb.is_satisfied())
    { // 三元组R1CS是否满足  < A , X > * < B , X > = < C , X >
        cout << "can not generate update proof" << endl;
        return r1cs_gg_ppzksnark_proof<ppzksnark_ppT>();
    }

    // 调用libsnark库中生成proof的函数
    return r1cs_gg_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

// 验证proof
template <typename ppzksnark_ppT>
bool verify_update_proof(r1cs_gg_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                  r1cs_gg_ppzksnark_proof<ppzksnark_ppT> proof,
                  uint256& id,
                  uint256& cmtU1,
                  uint256& cmtU2,
                  uint256& henc,
                  uint256& auth)
{
    typedef Fr<ppzksnark_ppT> FieldT;

    const r1cs_primary_input<FieldT> input = update_gadget<FieldT>::witness_map(
        id,
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

    update_gadget<FieldT> update(pb);
    update.generate_r1cs_constraints();// 生成约束

    // check conatraints
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    std::cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    
    // key pair generation
    r1cs_gg_ppzksnark_keypair<ppzksnark_ppT> keypair = r1cs_gg_ppzksnark_generator<ppzksnark_ppT>(constraint_system);

    return keypair;
}

template<typename ppzksnark_ppT> //--Agzs
bool test_update_gadget_with_instance(r1cs_gg_ppzksnark_keypair<ppzksnark_ppT> keypair)
{
    uint256 id = uint256S("11111Abcd");
    uint256 pkB = uint256S("22222Ba");
    uint256 pkD = uint256S("09cd53");

    uint256 sk = uint256S("9c0a334");
    uint256 r = uint256S("123456");
    uint256 ek = Compute_PRF(sk, r);

    CSHA256 hasher;
    uint256 cmtU1;
    hasher.Write(id.begin(), 32);
    hasher.Write(pkB.begin(), 32);
    hasher.Write(ek.begin(), 32);
    hasher.Write(r.begin(), 32);
    hasher.Finalize(cmtU1.begin());

    CSHA256 hasher1;
    uint256 cmtU2;
    hasher1.Write(id.begin(), 32);
    hasher1.Write(pkD.begin(), 32);
    hasher1.Write(ek.begin(), 32);
    hasher1.Write(r.begin(), 32);
    hasher1.Finalize(cmtU2.begin());

    uint256 aux = uint256S("654321");
    uint256 henc;
    CSHA256 hasher2;
    hasher2.Write(aux.begin(), 32);
    hasher2.Finalize(henc.begin());

    uint256 auth = Compute_PRF(sk, henc);

    // 生成proof
    cout << "Trying to generate proof..." << endl;

    struct timeval gen_start, gen_end;
    double updateTimeUse;
    gettimeofday(&gen_start,NULL);

    auto proof = generate_update_proof<default_r1cs_gg_ppzksnark_pp>(keypair.pk, 
                                                            id,
                                                            cmtU1,
                                                            cmtU2,
                                                            henc,
                                                            auth,
                                                            pkB,
                                                            pkD,
                                                            sk,
                                                            ek,
                                                            r);

    gettimeofday(&gen_end, NULL);
    updateTimeUse = gen_end.tv_sec - gen_start.tv_sec + (gen_end.tv_usec - gen_start.tv_usec)/1000000.0;
    printf("\n\nGen Update Proof Use Time:%fs\n\n", updateTimeUse);

    // verify proof
    if (!proof) {
        printf("generate update proof fail!!!\n");
        return false;
    } else {
        struct timeval ver_start, ver_end;
        double updateVerTimeUse;
        gettimeofday(&ver_start, NULL);

        bool result = verify_update_proof(keypair.vk, 
                                   *proof, 
                                   id,
                                   cmtU1,
                                   cmtU2,
                                   henc,
                                   auth
                                   );

        gettimeofday(&ver_end, NULL);
        updateVerTimeUse = ver_end.tv_sec - ver_start.tv_sec + (ver_end.tv_usec - ver_start.tv_usec)/1000000.0;
        printf("\n\nVer Update Proof Use Time:%fs\n\n", updateVerTimeUse);
         
        if (!result){
            cout << "Verifying update proof unsuccessfully!!!" << endl;
        } else {
            cout << "Verifying update proof successfully!!!" << endl;
        }
        
        return result;
    }
}

int main () {
    struct timeval t1, t2;
    double timeuse;
    gettimeofday(&t1,NULL);

    r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair = Setup<default_r1cs_gg_ppzksnark_pp>();

    gettimeofday(&t2,NULL);
    timeuse = t2.tv_sec - t1.tv_sec + (t2.tv_usec - t1.tv_usec)/1000000.0;
    printf("\n\nUpdate Setup Time Usage:%fs\n\n",timeuse);

    libff::print_header("#             testing update gadget");

    test_update_gadget_with_instance<default_r1cs_gg_ppzksnark_pp>(keypair);

    return 0;
}

