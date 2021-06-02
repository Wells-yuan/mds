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
class update_gadget : public gadget<FieldT> {
public:
    // Verifier inputs 验证者输入
    pb_variable_array<FieldT> zk_packed_inputs; // 合并为十进制
    pb_variable_array<FieldT> zk_unpacked_inputs; // 拆分为二进制
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker; // 二进制转十进制转换器

    std::shared_ptr<digest_variable<FieldT>> id;
    std::shared_ptr<digest_variable<FieldT>> pkB;
    std::shared_ptr<digest_variable<FieldT>> pkD;
    std::shared_ptr<digest_variable<FieldT>> ek;
    std::shared_ptr<digest_variable<FieldT>> r;

    std::shared_ptr<digest_variable<FieldT>> sk;
    std::shared_ptr<sha256_PRF_gadget<FieldT>> prf_to_ek; // symmetric key ek = SHA256(sk, r) 

    std::shared_ptr<digest_variable<FieldT>> auth;
    std::shared_ptr<digest_variable<FieldT>> henc;
    std::shared_ptr<sha256_PRF_gadget<FieldT>> prf_to_auth;// auth = SHA256(sk, henc)
    
    std::shared_ptr<digest_variable<FieldT>> cmtU1;
    std::shared_ptr<sha256_CMTU_gadget<FieldT>> commit_to_inputs_cmtU1;

    std::shared_ptr<digest_variable<FieldT>> cmtU2;
    std::shared_ptr<sha256_CMTU_gadget<FieldT>> commit_to_inputs_cmtU2;

    pb_variable<FieldT> ZERO;

    update_gadget(
        protoboard<FieldT>& pb
    ) : gadget<FieldT>(pb) {
        {

            zk_packed_inputs.allocate(pb, verifying_field_element_size()); 
            this->pb.set_input_sizes(verifying_field_element_size());

            alloc_uint256(zk_unpacked_inputs, id);
            alloc_uint256(zk_unpacked_inputs, cmtU1);
            alloc_uint256(zk_unpacked_inputs, cmtU2);
            alloc_uint256(zk_unpacked_inputs, henc);
            alloc_uint256(zk_unpacked_inputs, auth);

            assert(zk_unpacked_inputs.size() == verifying_input_bit_size()); // 判定输入长度

            unpacker.reset(new multipacking_gadget<FieldT>(
                pb,
                zk_unpacked_inputs,
                zk_packed_inputs,
                FieldT::capacity(),
                "unpacker"
            ));
        }

        ZERO.allocate(this->pb, FMT(this->annotation_prefix, "zero"));
        
        pkB.reset(new digest_variable<FieldT>(pb, 256, "B's public key"));
        pkD.reset(new digest_variable<FieldT>(pb, 256, "D's public key"));
        sk.reset(new digest_variable<FieldT>(pb, 256, "private key"));
        ek.reset(new digest_variable<FieldT>(pb, 256, "symmetric key"));
        r.reset(new digest_variable<FieldT>(pb, 256, "random number"));

        prf_to_ek.reset(new sha256_PRF_gadget<FieldT>( 
            pb,
            ZERO,
            sk->bits,   // 256bits private key
            r->bits,    // 256bits random number
            ek          // 256bits symmetric key
        ));

        prf_to_auth.reset(new sha256_PRF_gadget<FieldT>( 
            pb,
            ZERO,
            sk->bits,   // 256bits private key
            henc->bits,    // 256bits hash value
            auth          
        ));

        commit_to_inputs_cmtU1.reset(new sha256_CMTU_gadget<FieldT>( 
            pb,
            ZERO,
            id->bits,
            pkB->bits,
            ek->bits,
            r->bits,
            cmtU1
        ));

        commit_to_inputs_cmtU2.reset(new sha256_CMTU_gadget<FieldT>( 
            pb,
            ZERO,
            id->bits,
            pkD->bits,
            ek->bits,
            r->bits,
            cmtU2
        ));
    }

    // 约束函数，为commitment_with_add_and_less_gadget的变量生成约束
    void generate_r1cs_constraints() { 
        // The true passed here ensures all the inputs are boolean constrained.
        unpacker->generate_r1cs_constraints(true);

        // Constrain `ZERO`
        generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero(), "ZERO");

        id->generate_r1cs_constraints();
        cmtU1->generate_r1cs_constraints();
        cmtU2->generate_r1cs_constraints();
        henc->generate_r1cs_constraints();
        auth->generate_r1cs_constraints();
        pkB->generate_r1cs_constraints();
        pkD->generate_r1cs_constraints();
        sk->generate_r1cs_constraints();
        ek->generate_r1cs_constraints();
        r->generate_r1cs_constraints();

        prf_to_ek->generate_r1cs_constraints();

        prf_to_auth->generate_r1cs_constraints();

        commit_to_inputs_cmtU1->generate_r1cs_constraints();

        commit_to_inputs_cmtU2->generate_r1cs_constraints();
    }

    // 证据函数，生成证据
    void generate_r1cs_witness(
        uint256 id_data,
        uint256 cmtU1_data,
        uint256 cmtU2_data,
        uint256 henc_data,
        uint256 auth_data,
        uint256 pkB_data,
        uint256 pkD_data,
        uint256 sk_data,
        uint256 ek_data,
        uint256 r_data
    ) {
        // Witness `zero`
        this->pb.val(ZERO) = FieldT::zero();

        // [SANITY CHECK] Ensure the input is valid.
        id->bits.fill_with_bits(this->pb, uint256_to_bool_vector(id_data));
        cmtU1->bits.fill_with_bits(this->pb, uint256_to_bool_vector(cmtU1_data));
        cmtU2->bits.fill_with_bits(this->pb, uint256_to_bool_vector(cmtU2_data));
        henc->bits.fill_with_bits(this->pb, uint256_to_bool_vector(henc_data));
        auth->bits.fill_with_bits(this->pb, uint256_to_bool_vector(auth_data));
        
        pkB->bits.fill_with_bits(this->pb, uint256_to_bool_vector(pkB_data));
        pkD->bits.fill_with_bits(this->pb, uint256_to_bool_vector(pkD_data));
        sk->bits.fill_with_bits(this->pb, uint256_to_bool_vector(sk_data));
        ek->bits.fill_with_bits(this->pb, uint256_to_bool_vector(ek_data));
        r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(r_data));

        prf_to_ek->generate_r1cs_witness();

        prf_to_auth->generate_r1cs_witness();

        commit_to_inputs_cmtU1->generate_r1cs_witness();

        commit_to_inputs_cmtU2->generate_r1cs_witness();

        // This happens last, because only by now are all the verifier inputs resolved.
        unpacker->generate_r1cs_witness_from_bits();
    }

    // 将bit形式的私密输入 打包转换为 域上的元素
    static r1cs_primary_input<FieldT> witness_map(
        const uint256& id,
        const uint256& cmtU1,
        const uint256& cmtU2,
        const uint256& henc,
        const uint256& auth
    ) {
        std::vector<bool> verify_inputs;

        insert_uint256(verify_inputs, id);
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

        acc += 256; // id
        acc += 256; // cmtU1
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