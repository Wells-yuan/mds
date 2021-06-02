#include "utils.tcc"
#include "commitment.tcc"

/***********************************************************
 * 模块整合，主要包括验证proof时所需要的publicData的输入
 ***********************************************************
 * sha256_CMTA_gadget, Add_gadget, Comparison_gadget
 ***************************************************************
 * sha256(data+padding), 512bits < data.size() < 1024-64-1bits
 * *************************************************************
 * publicData: cmt_A_old, sn_A_old,  
 * privateData: value_old, r_A_old
 * *************************************************************
 * publicData: cmt_A_new, (value_s, balance)  
 * privateData: value_new, sn_A_new, r_A_new
 * *************************************************************
 * auxiliary: value_new == value_old + value_s
 *            value_s < balance
 **********************************************************/
template<typename FieldT>
class share_gadget : public gadget<FieldT> {
public:
    // Verifier inputs 验证者输入
    pb_variable_array<FieldT> zk_packed_inputs; // 合并为十进制
    pb_variable_array<FieldT> zk_unpacked_inputs; // 拆分为二进制
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker; // 二进制转十进制转换器

    /************************************************************************
     * std::shared_ptr<digest_variable<FieldT>> cmtA_old;  // this->cmtA_old
     * std::shared_ptr<digest_variable<FieldT>> sn_old;    // this->sn_old
     * std::shared_ptr<digest_variable<FieldT>> cmtA;      // this->cmtA
     * pb_variable_array<FieldT> value_s;                  // this->value_s
     * pb_variable_array<FieldT> balance_A;                // this->balance
     * *********************************************************************/

    // pb_variable_array<FieldT> value;
    // pb_variable_array<FieldT> value_old;
    // pb_variable_array<FieldT> value_s;
    
    // std::shared_ptr<digest_variable<FieldT>> sn; 
    // std::shared_ptr<digest_variable<FieldT>> sn_old; 

    // std::shared_ptr<note_gadget_with_comparison_and_addition_for_balance<FieldT>> ncab;

    // new serial number with sha256_PRF_gadget
    // std::shared_ptr<digest_variable<FieldT>> ek; // sn = SHA256(sk,r)


    std::shared_ptr<digest_variable<FieldT>> idA;
    std::shared_ptr<digest_variable<FieldT>> roleA;
    std::shared_ptr<digest_variable<FieldT>> pkB;
    std::shared_ptr<digest_variable<FieldT>> ekA;
    std::shared_ptr<digest_variable<FieldT>> rA;

    std::shared_ptr<digest_variable<FieldT>> idB;
    std::shared_ptr<digest_variable<FieldT>> ekB;
    std::shared_ptr<digest_variable<FieldT>> rB;

    std::shared_ptr<digest_variable<FieldT>> pkC;

    std::shared_ptr<digest_variable<FieldT>> sk;
    std::shared_ptr<sha256_PRF_gadget<FieldT>> prf_to_ek; // symmetric key ek = SHA256(sk, r) 

    std::shared_ptr<digest_variable<FieldT>> auth;
    std::shared_ptr<digest_variable<FieldT>> henc;
    std::shared_ptr<sha256_PRF_gadget<FieldT>> prf_to_auth;// auth = SHA256(sk, henc)
    
    std::shared_ptr<digest_variable<FieldT>> cmtA;
    std::shared_ptr<sha256_CMTA_gadget<FieldT>> commit_to_inputs_cmtA;

    std::shared_ptr<digest_variable<FieldT>> cmtU1;
    std::shared_ptr<sha256_CMTU_gadget<FieldT>> commit_to_inputs_cmtU1;

    std::shared_ptr<digest_variable<FieldT>> cmtU2;
    std::shared_ptr<sha256_CMTU_gadget<FieldT>> commit_to_inputs_cmtU2;

    pb_variable<FieldT> ZERO;

    share_gadget(
        protoboard<FieldT>& pb
    ) : gadget<FieldT>(pb) {
        // Verification
        {
            // 公开输入
            zk_packed_inputs.allocate(pb, verifying_field_element_size()); 
            this->pb.set_input_sizes(verifying_field_element_size());

            alloc_uint256(zk_unpacked_inputs, idA);
            alloc_uint256(zk_unpacked_inputs, idB);
            alloc_uint256(zk_unpacked_inputs, cmtA);
            alloc_uint256(zk_unpacked_inputs, cmtU1);
            alloc_uint256(zk_unpacked_inputs, cmtU2);
            alloc_uint256(zk_unpacked_inputs, henc);
            alloc_uint256(zk_unpacked_inputs, auth);

            assert(zk_unpacked_inputs.size() == verifying_input_bit_size()); // 判定输入长度

            // This gadget will ensure that all of the inputs we provide are
            // boolean constrained. 布尔约束 <=> 比特位, 打包
            unpacker.reset(new multipacking_gadget<FieldT>(
                pb,
                zk_unpacked_inputs,
                zk_packed_inputs,
                FieldT::capacity(),
                "unpacker"
            ));
        }

        ZERO.allocate(this->pb, FMT(this->annotation_prefix, "zero"));
        
        // 私密输入
        pkB.reset(new digest_variable<FieldT>(pb, 256, "B's public key"));
        pkC.reset(new digest_variable<FieldT>(pb, 256, "C's public key"));
        sk.reset(new digest_variable<FieldT>(pb, 256, "private key"));
        ekA.reset(new digest_variable<FieldT>(pb, 256, "idA's symmetric key"));
        ekB.reset(new digest_variable<FieldT>(pb, 256, "idB's symmetric key"));
        rA.reset(new digest_variable<FieldT>(pb, 256, "idA's random number"));
        rB.reset(new digest_variable<FieldT>(pb, 256, "idB's random number"));
        roleA.reset(new digest_variable<FieldT>(pb, 256, "hospital role A"));

        prf_to_ek.reset(new sha256_PRF_gadget<FieldT>(
            pb,
            ZERO,
            sk->bits,   // 256bits private key
            rB->bits,    // 256bits random number
            ekB         // 256bits symmetric key
        ));

        prf_to_auth.reset(new sha256_PRF_gadget<FieldT>( 
            pb,
            ZERO,
            sk->bits,   // 256bits private key
            henc->bits,    // 256bits hash value
            auth          
        ));

        commit_to_inputs_cmtA.reset(new sha256_CMTA_gadget<FieldT>( 
            pb,
            ZERO,
            idA->bits,
            roleA->bits,
            pkB->bits,
            ekA->bits,
            rA->bits,
            cmtA
        ));

        commit_to_inputs_cmtU1.reset(new sha256_CMTU_gadget<FieldT>( 
            pb,
            ZERO,
            idB->bits,
            pkB->bits,
            ekB->bits,
            rB->bits,
            cmtU1
        ));

        commit_to_inputs_cmtU2.reset(new sha256_CMTU_gadget<FieldT>( 
            pb,
            ZERO,
            idB->bits,
            pkC->bits,
            ekB->bits,
            rB->bits,
            cmtU2
        ));
    }

    // 约束函数
    void generate_r1cs_constraints() { 
        // The true passed here ensures all the inputs are boolean constrained.
        unpacker->generate_r1cs_constraints(true);

        // Constrain `ZERO`
        generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero(), "ZERO");

        idA->generate_r1cs_constraints();
        idB->generate_r1cs_constraints();
        cmtA->generate_r1cs_constraints();
        cmtU1->generate_r1cs_constraints();
        cmtU2->generate_r1cs_constraints();
        henc->generate_r1cs_constraints();
        auth->generate_r1cs_constraints();
        
        pkB->generate_r1cs_constraints();
        pkC->generate_r1cs_constraints();
        sk->generate_r1cs_constraints();
        ekA->generate_r1cs_constraints();
        ekB->generate_r1cs_constraints();
        rA->generate_r1cs_constraints();
        rB->generate_r1cs_constraints();
        roleA->generate_r1cs_constraints();

        prf_to_ek->generate_r1cs_constraints();

        prf_to_auth->generate_r1cs_constraints();

        commit_to_inputs_cmtA->generate_r1cs_constraints();
        commit_to_inputs_cmtU1->generate_r1cs_constraints();
        commit_to_inputs_cmtU2->generate_r1cs_constraints();
    }

    // 证据函数，生成证据
    void generate_r1cs_witness(
        uint256 idA_data,
        uint256 idB_data,
        uint256 cmtA_data,
        uint256 cmtU1_data,
        uint256 cmtU2_data,
        uint256 henc_data,
        uint256 auth_data,

        uint256 pkB_data,
        uint256 pkC_data,
        uint256 sk_data,
        uint256 ekA_data,
        uint256 ekB_data,
        uint256 rA_data,
        uint256 rB_data,
        uint256 roleA_data
    ) {
        // Witness `zero`
        this->pb.val(ZERO) = FieldT::zero();

        // [SANITY CHECK] Ensure the input is valid.
        idA->bits.fill_with_bits(this->pb, uint256_to_bool_vector(idA_data));
        idB->bits.fill_with_bits(this->pb, uint256_to_bool_vector(idB_data));
        cmtA->bits.fill_with_bits(this->pb, uint256_to_bool_vector(cmtA_data));
        cmtU1->bits.fill_with_bits(this->pb, uint256_to_bool_vector(cmtU1_data));
        cmtU2->bits.fill_with_bits(this->pb, uint256_to_bool_vector(cmtU2_data));
        henc->bits.fill_with_bits(this->pb, uint256_to_bool_vector(henc_data));
        auth->bits.fill_with_bits(this->pb, uint256_to_bool_vector(auth_data));
        pkB->bits.fill_with_bits(this->pb, uint256_to_bool_vector(pkB_data));
        pkC->bits.fill_with_bits(this->pb, uint256_to_bool_vector(pkC_data));
        sk->bits.fill_with_bits(this->pb, uint256_to_bool_vector(sk_data));
        ekA->bits.fill_with_bits(this->pb, uint256_to_bool_vector(ekA_data));
        ekB->bits.fill_with_bits(this->pb, uint256_to_bool_vector(ekB_data));
        rA->bits.fill_with_bits(this->pb, uint256_to_bool_vector(rA_data));
        rB->bits.fill_with_bits(this->pb, uint256_to_bool_vector(rB_data));
        roleA->bits.fill_with_bits(this->pb, uint256_to_bool_vector(roleA_data));

        prf_to_ek->generate_r1cs_witness();

        prf_to_auth->generate_r1cs_witness();

        commit_to_inputs_cmtA->generate_r1cs_witness();

        commit_to_inputs_cmtU1->generate_r1cs_witness();
        
        commit_to_inputs_cmtU2->generate_r1cs_witness();

        // This happens last, because only by now are all the verifier inputs resolved.
        unpacker->generate_r1cs_witness_from_bits();
    }

    // 将bit形式的公开输入 打包转换为 域上的元素
    static r1cs_primary_input<FieldT> witness_map(
        const uint256& idA,
        const uint256& idB,
        const uint256& cmtA,
        const uint256& cmtU1,
        const uint256& cmtU2,
        const uint256& henc,
        const uint256& auth
    ) {
        std::vector<bool> verify_inputs;

        insert_uint256(verify_inputs, idA);
        insert_uint256(verify_inputs, idB);
        insert_uint256(verify_inputs, cmtA);
        insert_uint256(verify_inputs, cmtU1);
        insert_uint256(verify_inputs, cmtU2);
        insert_uint256(verify_inputs, henc);
        insert_uint256(verify_inputs, auth);

        assert(verify_inputs.size() == verifying_input_bit_size());
        auto verify_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(verify_inputs);
        assert(verify_field_elements.size() == verifying_field_element_size());
        return verify_field_elements;
    }

    // 计算输入元素的bit大小
    static size_t verifying_input_bit_size() {
        size_t acc = 0;

        acc += 256; // idA
        acc += 256; // idB
        acc += 256; // cmtA
        acc += 256; // cmtU2
        acc += 256; // cmtU2
        acc += 256; // henc
        acc += 256; // auth
        
        return acc;
    }

    // 计算域上元素的组数
    static size_t verifying_field_element_size() {
        return div_ceil(verifying_input_bit_size(), FieldT::capacity());
    }

    // 分配空间，打包追加
    void alloc_uint256(
        pb_variable_array<FieldT>& packed_into,
        std::shared_ptr<digest_variable<FieldT>>& var
    ) {
        var.reset(new digest_variable<FieldT>(this->pb, 256, ""));
        packed_into.insert(packed_into.end(), var->bits.begin(), var->bits.end());
    }
};