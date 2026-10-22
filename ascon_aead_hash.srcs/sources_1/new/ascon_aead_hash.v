`timescale 1ns / 1ps
// ============================================================================
// ascon_aead_hash.v -- unified Ascon-AEAD128 / Ascon-Hash256 core
// (NIST SP 800-232).  Control FSM + shared datapath, one permutation round.
//
// mode: 0 = Hash256, 1 = AEAD128 encrypt, 2 = AEAD128 decrypt (sampled on start)
// key / nonce must be held stable while busy (they are not copied internally).
// Blocks, key, nonce, tag and outputs are little-endian integers of their
// byte strings (byte 0 in bits [7:0]).  Hash blocks use in_data[63:0] and
// squeeze outputs appear in out_data[63:0] (out_len = 8).
// AEAD C/P output is valid in the cycle the input block is accepted; a
// message block is only accepted while out_ready is high.
// ============================================================================
module ascon_aead_hash #(
    parameter integer SPLIT_ROUND  = 0,   // 1: register between S-box and linear layer
    parameter integer MERGE_ABSORB = 0    // 1: absorb shares the first round cycle
) (
    input  wire         clk,
    input  wire         rst,            // synchronous, active high
    // ---- command ----------------------------------------------------------
    input  wire         start,
    input  wire [1:0]   mode,
    input  wire [127:0] key,
    input  wire [127:0] nonce,
    output wire         busy,
    // ---- input stream -----------------------------------------------------
    input  wire         in_valid,
    input  wire [127:0] in_data,
    input  wire [4:0]   in_len,
    input  wire         in_last,
    input  wire         in_ad,
    output wire         in_ready,
    output wire         in_ready_ad,
    output wire         in_ready_msg,
    // ---- output stream ----------------------------------------------------
    output wire         out_valid,
    output wire [127:0] out_data,
    output wire [4:0]   out_len,
    output wire         out_last,
    input  wire         out_ready,
    // ---- tag --------------------------------------------------------------
    output wire         tag_valid,
    output wire [127:0] tag
);
    wire       state_we, load_init, init_is_hash, mode_hash, absorb_ct;
    wire       do_round, round_half;
    wire [3:0] round_idx;
    wire       xor_blk, blk_internal, blk_full;
    wire [4:0] blk_len;
    wire       xor_key_init, xor_key_fin, xor_dsep;

    ascon_aead_hash_control #(
        .SPLIT_ROUND  (SPLIT_ROUND),
        .MERGE_ABSORB (MERGE_ABSORB)
    ) u_ctrl (
        .clk          (clk),
        .rst          (rst),
        .start        (start),
        .mode         (mode),
        .busy         (busy),
        .tag_valid    (tag_valid),
        .in_valid     (in_valid),
        .in_len       (in_len),
        .in_last      (in_last),
        .in_ad        (in_ad),
        .in_ready     (in_ready),
        .in_ready_ad  (in_ready_ad),
        .in_ready_msg (in_ready_msg),
        .out_valid    (out_valid),
        .out_len      (out_len),
        .out_last     (out_last),
        .out_ready    (out_ready),
        .state_we     (state_we),
        .load_init    (load_init),
        .init_is_hash (init_is_hash),
        .mode_hash    (mode_hash),
        .absorb_ct    (absorb_ct),
        .do_round     (do_round),
        .round_idx    (round_idx),
        .round_half   (round_half),
        .xor_blk      (xor_blk),
        .blk_internal (blk_internal),
        .blk_len      (blk_len),
        .blk_full     (blk_full),
        .xor_key_init (xor_key_init),
        .xor_key_fin  (xor_key_fin),
        .xor_dsep     (xor_dsep)
    );

    ascon_aead_hash_datapath #(
        .SPLIT_ROUND  (SPLIT_ROUND),
        .MERGE_ABSORB (MERGE_ABSORB)
    ) u_dp (
        .clk          (clk),
        .rst          (rst),
        .state_we     (state_we),
        .load_init    (load_init),
        .init_is_hash (init_is_hash),
        .mode_hash    (mode_hash),
        .absorb_ct    (absorb_ct),
        .do_round     (do_round),
        .round_idx    (round_idx),
        .round_half   (round_half),
        .xor_blk      (xor_blk),
        .blk_internal (blk_internal),
        .blk_len      (blk_len),
        .blk_full     (blk_full),
        .xor_key_init (xor_key_init),
        .xor_key_fin  (xor_key_fin),
        .xor_dsep     (xor_dsep),
        .key          (key),
        .nonce        (nonce),
        .in_data      (in_data),
        .out_data     (out_data),
        .tag          (tag)
    );
endmodule
