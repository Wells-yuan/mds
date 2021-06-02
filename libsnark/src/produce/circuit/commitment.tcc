/***************************************************************
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
 * *************************************************************/
template<typename FieldT>
class sha256_CMTA_gadget : gadget<FieldT> {
private:
    std::shared_ptr<block_variable<FieldT>> block1;
    std::shared_ptr<block_variable<FieldT>> block2;
    std::shared_ptr<block_variable<FieldT>> block3;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher1;
    std::shared_ptr<digest_variable<FieldT>> intermediate_hash1; // 中间hash值
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher2;
    std::shared_ptr<digest_variable<FieldT>> intermediate_hash2;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher3;

public:
    sha256_CMTA_gadget(              // cmt_A = sha256(id, role, pk, ek, r) for Mint
        protoboard<FieldT> &pb,
        pb_variable<FieldT>& ZERO,
        pb_variable_array<FieldT>& id,      // 256bits identity of medical data
        pb_variable_array<FieldT>& role,      // 256bits identity of medical facility
        pb_variable_array<FieldT>& pk, // 256bits public key
        pb_variable_array<FieldT>& ek, // 256bits symmetric key
        pb_variable_array<FieldT>& rho,      // 256bits random number
        std::shared_ptr<digest_variable<FieldT>> cmtA // 256bits hash
    ) : gadget<FieldT>(pb, "sha256_CMTA_gadget") {

        // pb_variable_array<FieldT> first_of_r(rho.begin(), rho.begin()+96);
        // pb_variable_array<FieldT> last_of_r(rho.begin()+96, rho.end());

        intermediate_hash1.reset(new digest_variable<FieldT>(pb, 256, ""));
        intermediate_hash2.reset(new digest_variable<FieldT>(pb, 256, ""));

        // final padding = base_padding + length
        pb_variable_array<FieldT> length_padding =
            from_bits({
                1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, // 6*4*8 = 192bits
                // length of message (1280 bits)
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,1,0,1, 0,0,0,0,0,0,0,0 // 8*8 = 64bits
            }, ZERO);

        block1.reset(new block_variable<FieldT>(pb, {
            id,           // 256bits
            role,      // 256bits
        }, "sha256_CMTA_gadget_block1"));

        block2.reset(new block_variable<FieldT>(pb, {
            pk,      // 256bits
            ek,  // 256bits
        }, "sha256_CMTA_gadget_block2"));

        block3.reset(new block_variable<FieldT>(pb, {
            rho,      // 256bits
            length_padding  // 256bits
        }, "sha256_CMTA_gadget_block3"));

        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        hasher1.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block1->bits,
            *intermediate_hash1,
        "sha256_CMTA_block_hash1"));

        pb_linear_combination_array<FieldT> IV2(intermediate_hash1->bits); // hash迭代

        hasher2.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV2,
            block2->bits,
            *intermediate_hash2,
        "sha256_CMTA_block_hash2"));

        pb_linear_combination_array<FieldT> IV3(intermediate_hash2->bits); // hash迭代

        hasher3.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV3,
            block3->bits,
            *cmtA,
        "sha256_CMTA_block_hash3"));

    }

    void generate_r1cs_constraints() {
        // TODO: This may not be necessary if SHA256 constrains
        // its output digests to be boolean anyway.
        intermediate_hash1->generate_r1cs_constraints();
        intermediate_hash2->generate_r1cs_constraints();

        hasher1->generate_r1cs_constraints();
        hasher2->generate_r1cs_constraints();
        hasher3->generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        hasher1->generate_r1cs_witness();
        hasher2->generate_r1cs_witness();
        hasher3->generate_r1cs_witness();
    }
};

template<typename FieldT>
class sha256_CMTU_gadget : gadget<FieldT> {
private:
    std::shared_ptr<block_variable<FieldT>> block1;
    std::shared_ptr<block_variable<FieldT>> block2;
    std::shared_ptr<block_variable<FieldT>> block3;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher1;
    std::shared_ptr<digest_variable<FieldT>> intermediate_hash1; // 中间hash值
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher2;
    std::shared_ptr<digest_variable<FieldT>> intermediate_hash2;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher3;

public:
    sha256_CMTU_gadget(                // cmt_s = sha256(value, pk_B, r, sn_A, padding)
        protoboard<FieldT> &pb,
        pb_variable<FieldT>& ZERO,
        pb_variable_array<FieldT>& id,      // 256bits identity of medical data
        pb_variable_array<FieldT>& pk, // 256bits public key
        pb_variable_array<FieldT>& ek, // 256bits symmetric key
        pb_variable_array<FieldT>& rho,      // 256bits random number
        std::shared_ptr<digest_variable<FieldT>> cmtU // 256bits hash
    ) : gadget<FieldT>(pb, "sha256_CMTU_gadget") {

        // final padding = base_padding + length
        pb_variable_array<FieldT> length_padding =
            from_bits({
                1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, // 14*4*8 = 448bits

                // length of message (1024 bits)
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,1,0,0, 0,0,0,0,0,0,0,0 // 2*4*8 = 64bits
            }, ZERO); // 9*4*8=288bits

        // pb_variable_array<FieldT> first_of_ek(ek.begin(), ek.begin()+96);
        // pb_variable_array<FieldT> last_of_ek(ek.begin()+96, ek.end());

        intermediate_hash1.reset(new digest_variable<FieldT>(pb, 256, ""));
        intermediate_hash2.reset(new digest_variable<FieldT>(pb, 256, ""));

        block1.reset(new block_variable<FieldT>(pb, {
            id,               // 256bits
            pk,          // 256bits
        }, "sha256_CMTU_gadget_block1"));

        block2.reset(new block_variable<FieldT>(pb, {
            ek,             // 256bits
            rho,            // 256bits
        }, "sha256_CMTU_gadget_block2"));

        block3.reset(new block_variable<FieldT>(pb, {
           length_padding          // 512bits
        }, "sha256_CMTU_gadget_block3"));

        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        hasher1.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block1->bits,
            *intermediate_hash1,
        "sha256_CMTU_block_hash1"));

        pb_linear_combination_array<FieldT> IV2(intermediate_hash1->bits); // hash迭代

        hasher2.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV2,
            block2->bits,
            *intermediate_hash2,
        "sha256_CMTU_block_hash2"));

        pb_linear_combination_array<FieldT> IV3(intermediate_hash2->bits); // hash迭代

        hasher3.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV3,
            block3->bits,
            *cmtU,
        "sha256_CMTU_block_hash3"));

    }

    void generate_r1cs_constraints() {
        // TODO: This may not be necessary if SHA256 constrains
        // its output digests to be boolean anyway.
        intermediate_hash1->generate_r1cs_constraints();
        intermediate_hash2->generate_r1cs_constraints();

        hasher1->generate_r1cs_constraints();
        hasher2->generate_r1cs_constraints();
        hasher3->generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        hasher1->generate_r1cs_witness();
        hasher2->generate_r1cs_witness();
        hasher3->generate_r1cs_witness();
    }
};

template<typename FieldT>
class sha256_PRF_gadget : gadget<FieldT> {
private:
    std::shared_ptr<block_variable<FieldT>> block1;
    std::shared_ptr<block_variable<FieldT>> block2;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher1;
    std::shared_ptr<digest_variable<FieldT>> intermediate_hash; // 中间hash值
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher2;

public:
    sha256_PRF_gadget(              // sn = sha256(sk, r, padding) or r_v = CRH(pk||r_new) 
        protoboard<FieldT> &pb,
        pb_variable<FieldT>& ZERO,
        pb_variable_array<FieldT>& sk, // 256bits private key
        pb_variable_array<FieldT>& rho,      // 256bits random number
        std::shared_ptr<digest_variable<FieldT>> sn // 256bits serial number (hash)
    ) : gadget<FieldT>(pb, "sha256_PRF_gadget") {

        intermediate_hash.reset(new digest_variable<FieldT>(pb, 256, ""));

        // final padding = base_padding + length
        pb_variable_array<FieldT> length_padding =
            from_bits({
                1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, // 14*4*8 = 448bits
                // length of message (512 bits)
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,1,0, 0,0,0,0,0,0,0,0 // 2*4*8 = 64bits
            }, ZERO); // 16*4*8=512bits

        block1.reset(new block_variable<FieldT>(pb, {
            sk,      // 256bits
            rho        // 256bits
        }, "sha256_PRF_block1"));

        block2.reset(new block_variable<FieldT>(pb, {
            length_padding  // 512bits
        }, "sha256_PRF_block2"));

        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        hasher1.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block1->bits,
            *intermediate_hash,
        "sha256_PRF_hash1"));

        pb_linear_combination_array<FieldT> IV2(intermediate_hash->bits); // hash迭代

        hasher2.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV2,
            block2->bits,
            *sn,
        "sha256_PRF_hash2"));
    }

    void generate_r1cs_constraints() {
        // TODO: This may not be necessary if SHA256 constrains
        // its output digests to be boolean anyway.
        intermediate_hash->generate_r1cs_constraints();

        hasher1->generate_r1cs_constraints();
        hasher2->generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        hasher1->generate_r1cs_witness();
        hasher2->generate_r1cs_witness();
    }
};
