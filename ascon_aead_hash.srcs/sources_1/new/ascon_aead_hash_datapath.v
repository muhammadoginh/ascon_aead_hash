`timescale 1ns / 1ps
// ============================================================================
// ascon_aead_hash_datapath.v -- shared datapath for Ascon-AEAD128 and
// Ascon-Hash256 (NIST SP 800-232)
//
//   * one 320-bit state register, one combinational round instance
//     (iterative round folding: p12 = 12 cycles, p8 = 8 cycles)
//   * one 128-bit padding/masking unit shared by hash absorb, AEAD encrypt
//     and AEAD decrypt ("plaintext-centric" absorb: decrypt feeds P = S ^ C
//     back through the same padding unit, so S ^ pad(P) == C for valid bytes)
//   * all XOR injections (block, key, domain separation) go through one
//     320-bit XOR; with MERGE_ABSORB = 1 it feeds the round so the absorb
//     shares the cycle of the first round, with MERGE_ABSORB = 0 it is a
//     separate mux leg (one absorb cycle, round path free of pad logic)
//   * hash initialisation is the precomputed p12(IV), loaded in one cycle
//   * the state register is written only when state_we is set, so the
//     injection controls need no qualification by the accept condition
//
// Byte order: a 128-bit block is the little-endian integer of its 16 bytes
// (byte 0 in bits [7:0]); S0 holds bytes 0..7, S1 bytes 8..15.  Key, nonce,
// tag and output follow the same convention.
//
// SPLIT_ROUND = 1 inserts a register between the substitution layer and the
// linear layer; each round then takes two cycles (shorter critical path).
// ============================================================================
module ascon_aead_hash_datapath #(
    parameter integer SPLIT_ROUND  = 0,
    parameter integer MERGE_ABSORB = 0
) (
    input  wire         clk,
    input  wire         rst,            // synchronous, active high
    // ---- control ---------------------------------------------------------
    input  wire         state_we,       // write state register
    input  wire         load_init,      // load initial state
    input  wire         init_is_hash,   // ... p12(hash IV) instead of {IV, K, N}
    input  wire         mode_hash,      // 1: Ascon-Hash256 (output select)
    input  wire         absorb_ct,      // block is ciphertext: absorb P = S ^ C
    input  wire         do_round,       // state_d = round(round_in)
    input  wire [3:0]   round_idx,      // round constant index 0..11
    input  wire         round_half,     // SPLIT_ROUND only: 0 S-box half, 1 linear half
    input  wire         xor_blk,        // inject padded block into S0/S1
    input  wire         blk_internal,   // block is the internally generated pad block
    input  wire [4:0]   blk_len,        // valid bytes in block (0..16 AEAD, 0..8 hash)
    input  wire         blk_full,       // block is a full rate block: no padding byte
    input  wire         xor_key_init,   // K -> S3,S4 (after init and after final p12)
    input  wire         xor_key_fin,    // K -> S2,S3 (before final p12)
    input  wire         xor_dsep,       // domain separation bit -> S4[63]
    // ---- data ------------------------------------------------------------
    input  wire [127:0] key,
    input  wire [127:0] nonce,
    input  wire [127:0] in_data,
    output wire [127:0] out_data,       // AEAD: masked C/P of current block, hash: {0, S0}
    output wire [127:0] tag             // {S4, S3}
);
    // SP 800-232 constants
    localparam [63:0] AEAD128_IV = 64'h00001000808c0001;
    // p12 applied to the Ascon-Hash256 IV {0x0000080100cc0002, 0, 0, 0, 0}
    localparam [63:0] HASH256_S0 = 64'h9b1e5494e934d681;
    localparam [63:0] HASH256_S1 = 64'h4bc3a01e333751d2;
    localparam [63:0] HASH256_S2 = 64'hae65396c6b34b81a;
    localparam [63:0] HASH256_S3 = 64'h3c7fd4a4d56a4db3;
    localparam [63:0] HASH256_S4 = 64'h1a5c464906c5976d;

    // ------------------------------------------------------------------
    // State register
    // ------------------------------------------------------------------
    reg  [319:0] state_q;
    wire [63:0]  s0 = state_q[319:256];
    wire [63:0]  s1 = state_q[255:192];
    wire [63:0]  s3 = state_q[127:64];
    wire [63:0]  s4 = state_q[63:0];

    // ------------------------------------------------------------------
    // Shared padding / masking unit (hash absorb, encrypt, decrypt)
    // ------------------------------------------------------------------
    wire [127:0] blk_in   = blk_internal ? 128'd0 : in_data;
    wire [127:0] rate_q   = {s1, s0};
    wire [127:0] rate_xor = rate_q ^ blk_in;               // C = S ^ P  or  P = S ^ C
    wire [127:0] pt_eff   = absorb_ct ? rate_xor : blk_in;  // value absorbed into the rate

    reg  [127:0] byte_mask;                                 // bytes 0 .. blk_len-1
    reg  [127:0] pad_byte;                                  // 0x01 at byte blk_len
    integer j;
    always @(*) begin
        for (j = 0; j < 16; j = j + 1) begin
            byte_mask[8*j +: 8] = (j < blk_len) ? 8'hff : 8'h00;
            pad_byte [8*j +: 8] = (!blk_full && blk_len[3:0] == j[3:0]) ? 8'h01 : 8'h00;
        end
    end

    wire [127:0] absorb = (pt_eff & byte_mask) | pad_byte;

    assign out_data = mode_hash ? {64'd0, s0} : (rate_xor & byte_mask);

    // ------------------------------------------------------------------
    // XOR injection vector (applied on the round input)
    // ------------------------------------------------------------------
    wire [63:0] k_lo = key[63:0];       // key bytes 0..7
    wire [63:0] k_hi = key[127:64];     // key bytes 8..15

    wire [63:0] xv0 = xor_blk ? absorb[63:0]   : 64'd0;
    wire [63:0] xv1 = xor_blk ? absorb[127:64] : 64'd0;
    wire [63:0] xv2 = xor_key_fin  ? k_lo : 64'd0;
    wire [63:0] xv3 = (xor_key_fin  ? k_hi : 64'd0) ^ (xor_key_init ? k_lo : 64'd0);
    wire [63:0] xv4 = (xor_key_init ? k_hi : 64'd0) ^ {xor_dsep, 63'd0};

    wire [319:0] round_in = state_q ^ {xv0, xv1, xv2, xv3, xv4};

    // Round source: with MERGE_ABSORB the injections sit in front of the round
    // (absorb and first round in one cycle).  Otherwise the round operates on
    // the registered state only, so the padding / injection logic is a
    // separate mux leg and never in series with the round's critical path.
    wire [319:0] round_src = (MERGE_ABSORB != 0) ? round_in : state_q;

    // ------------------------------------------------------------------
    // Initial states
    // ------------------------------------------------------------------
    wire [319:0] init_aead = {AEAD128_IV, k_lo, k_hi, nonce[63:0], nonce[127:64]};
    wire [319:0] init_hash = {HASH256_S0, HASH256_S1, HASH256_S2, HASH256_S3, HASH256_S4};
    wire [319:0] init_vec  = init_is_hash ? init_hash : init_aead;

    // ------------------------------------------------------------------
    // Single shared round (optionally split in two pipeline halves)
    // ------------------------------------------------------------------
    wire [319:0] round_result;

    generate
        if (SPLIT_ROUND == 0) begin : g_full_round
            ascon_round u_round (
                .round_idx (round_idx),
                .x_in      (round_src),
                .x_out     (round_result)
            );
        end else begin : g_split_round
            wire [319:0] sbox_out;
            reg  [319:0] mid_q;

            ascon_round_sbox u_sbox (
                .round_idx (round_idx),
                .x_in      (round_src),
                .x_out     (sbox_out)
            );

            // S-box half: capture here (state_we is low in that cycle)
            always @(posedge clk)
                if (do_round && !round_half)
                    mid_q <= sbox_out;

            ascon_round_linear u_lin (
                .x_in  (mid_q),
                .x_out (round_result)
            );
        end
    endgenerate

    wire [319:0] state_d = load_init ? init_vec :
                           do_round  ? round_result :
                                       round_in;      // standalone XOR (absorb / key)

    always @(posedge clk) begin
        if (rst)           state_q <= 320'd0;
        else if (state_we) state_q <= state_d;
    end

    assign tag = {s4, s3};
endmodule
