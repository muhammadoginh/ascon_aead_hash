`timescale 1ns / 1ps
// ============================================================================
// ascon_aead_hash_control.v -- FSM for the unified Ascon-AEAD128 / Hash256 core
//
// Operation (mode latched on start):
//   0 = Ascon-Hash256   : absorb 64-bit blocks (p12 each), squeeze 4 x 64 bit
//   1 = AEAD128 encrypt : p12 init, AD blocks (p8), PT blocks (p8), p12 final
//   2 = AEAD128 decrypt : same schedule, plaintext-centric absorb
//
// Block interface: one block per handshake (in_valid & in_ready).
//   in_len  = valid bytes (hash 0..8, AEAD 0..16); non-last blocks must be full
//   in_last = last block of the AD stream or of the message stream
//   in_ad   = block belongs to the associated data (AEAD only)
// A last block that is full (len == rate) is followed automatically by the
// internally generated padding block; a driver may instead send an explicit
// empty last block (len = 0, last = 1).  Both conventions are accepted.
//
// Parameters
//   SPLIT_ROUND  1: register between S-box and linear layer, 2 cycles / round
//   MERGE_ABSORB 1: a block is absorbed in the same cycle as the first round of
//                   its permutation (8 cycles / AEAD block, 12 / hash block);
//                0: the absorb XOR takes its own cycle (9 / 13 cycles) which
//                   keeps the padding logic out of the round's critical path.
//
// Timing structure: the 320-bit state register is written through state_we,
// so none of the XOR-injection controls has to be qualified by the
// input-dependent accept condition; they are plain functions of FSM flags.
// ============================================================================
module ascon_aead_hash_control #(
    parameter integer SPLIT_ROUND  = 0,
    parameter integer MERGE_ABSORB = 0
) (
    input  wire       clk,
    input  wire       rst,            // synchronous, active high
    // ---- command ----------------------------------------------------------
    input  wire       start,          // pulse; aborts any running operation
    input  wire [1:0] mode,           // sampled with start
    output wire       busy,
    output wire       tag_valid,      // AEAD tag available (until next start)
    // ---- input stream -----------------------------------------------------
    input  wire       in_valid,
    input  wire [4:0] in_len,
    input  wire       in_last,
    input  wire       in_ad,
    output wire       in_ready,       // for the block currently presented
    output wire       in_ready_ad,    // would accept an AD block now
    output wire       in_ready_msg,   // would accept a message block now
    // ---- output stream ----------------------------------------------------
    output wire       out_valid,
    output wire [4:0] out_len,
    output wire       out_last,
    input  wire       out_ready,
    // ---- datapath control -------------------------------------------------
    output wire       state_we,       // write the state register this cycle
    output wire       load_init,      // load the initial state (with start)
    output wire       init_is_hash,   // ... hash constants (else {IV, K, N})
    output wire       mode_hash,      // operation is Hash256
    output wire       absorb_ct,      // current block is ciphertext (decrypt, non-AD)
    output wire       do_round,       // state_d = round(round_in) (else round_in)
    output wire [3:0] round_idx,
    output wire       round_half,     // SPLIT_ROUND: 1 = linear half
    output wire       xor_blk,        // inject padded block into S0/S1
    output wire       blk_internal,   // block is the internal padding block
    output wire [4:0] blk_len,
    output wire       blk_full,
    output wire       xor_key_init,   // K -> S3,S4
    output wire       xor_key_fin,    // K -> S2,S3
    output wire       xor_dsep        // domain separation -> S4[63]
);
    localparam SPLIT = (SPLIT_ROUND  != 0);
    localparam MERGE = (MERGE_ABSORB != 0);

    localparam [2:0] S_IDLE    = 3'd0;
    localparam [2:0] S_WAIT    = 3'd1;   // waiting for a block
    localparam [2:0] S_ROUND   = 3'd2;   // iterating the permutation
    localparam [2:0] S_KEYX    = 3'd3;   // final K xor into S3,S4
    localparam [2:0] S_SQUEEZE = 3'd4;   // hash output block offered
    localparam [2:0] S_DONE    = 3'd5;

    localparam [2:0] PH_INIT = 3'd0;     // AEAD initialisation p12
    localparam [2:0] PH_AD   = 3'd1;     // AD block p8
    localparam [2:0] PH_MSG  = 3'd2;     // PT/CT block p8, or hash absorb p12
    localparam [2:0] PH_FIN  = 3'd3;     // AEAD finalisation p12
    localparam [2:0] PH_SQZ  = 3'd4;     // hash squeeze p12

    reg [2:0] state_q;
    reg [2:0] phase_q;
    (* max_fanout = 32 *) reg [1:0] mode_q;
    reg [3:0] ridx_q;
    reg       half_q;
    reg       key_pend_q;    // K -> S3,S4 still to be applied (after init p12)
    reg       dsep_pend_q;   // domain separation still to be applied
    (* max_fanout = 32 *) reg pad_pend_q;   // internal padding block must be absorbed next
    reg       pad_ad_q;      // ... and it belongs to the AD stream
    reg [1:0] sqz_q;         // squeeze blocks delivered

    // ------------------------------------------------------------------
    // Decodes (registered state only, no input dependence)
    // ------------------------------------------------------------------
    assign mode_hash = (mode_q == 2'd0);
    wire   mode_dec  = (mode_q == 2'd2);
    wire   aead      = ~mode_hash;
    assign init_is_hash = (mode == 2'd0);

    (* max_fanout = 32 *) wire in_wait    = (state_q == S_WAIT);
    (* max_fanout = 32 *) wire in_round   = (state_q == S_ROUND);
    wire in_keyx    = (state_q == S_KEYX);
    wire in_squeeze = (state_q == S_SQUEEZE);

    // ------------------------------------------------------------------
    // Block presented in S_WAIT (internal padding block has priority)
    // ------------------------------------------------------------------
    wire       blk_avail = pad_pend_q | in_valid;
    assign     blk_internal = pad_pend_q;
    wire       blk_ad    = pad_pend_q ? pad_ad_q : (in_ad & aead);
    wire       blk_last  = pad_pend_q ? 1'b1 : in_last;
    assign     blk_len   = pad_pend_q ? 5'd0 : in_len;
    wire [4:0] rate_bytes = mode_hash ? 5'd8 : 5'd16;
    assign     blk_full  = (blk_len == rate_bytes);
    wire       blk_msg   = ~blk_ad;
    wire       emits_out = aead & blk_msg & ~pad_pend_q;          // C/P produced this cycle
    wire       fin       = aead & blk_msg & blk_last & ~blk_full; // final message block

    wire accept = in_wait & ~start & blk_avail & (~emits_out | out_ready);

    assign in_ready_ad  = in_wait & ~start & ~pad_pend_q & aead;
    assign in_ready_msg = in_wait & ~start & ~pad_pend_q & (mode_hash | out_ready);
    assign in_ready     = (in_ad & aead) ? in_ready_ad : in_ready_msg;

    // ------------------------------------------------------------------
    // Round sequencing
    // ------------------------------------------------------------------
    wire round_last_cycle = SPLIT ? half_q : 1'b1;
    wire round_exit       = in_round & round_last_cycle & (ridx_q == 4'd11);
    wire sqz_next         = in_squeeze & out_ready & ~start & (sqz_q != 2'd3);
    wire [3:0] first_idx  = (mode_hash | fin) ? 4'd0 : 4'd4;    // p12 or p8

    (* max_fanout = 32 *) wire do_round_i = in_round | (MERGE ? (accept | sqz_next) : 1'b0);
    assign load_init  = start;
    assign do_round   = do_round_i;
    assign round_idx  = in_round ? ridx_q : first_idx;
    assign round_half = in_round ? half_q : 1'b0;

    // XOR injections are active for the whole S_WAIT phase; they only take
    // effect in the cycle the state register is written (accept).
    (* max_fanout = 32 *) wire xor_key_init_i = (in_wait & key_pend_q) | in_keyx;
    (* max_fanout = 32 *) wire xor_key_fin_i  = in_wait & fin;
    (* max_fanout = 32 *) wire absorb_ct_i    = mode_dec & blk_msg;
    assign xor_blk      = in_wait;
    assign xor_key_init = xor_key_init_i;
    assign xor_key_fin  = xor_key_fin_i;
    assign xor_dsep     = in_wait & dsep_pend_q & blk_msg;
    assign absorb_ct    = absorb_ct_i;

    // State register write enable
    wire round_we  = in_round & (SPLIT ? half_q : 1'b1);        // linear half writes
    wire accept_we = accept & ~(MERGE && SPLIT);                 // merged + split: S-box half only
    wire sqz_we    = (MERGE && !SPLIT) ? sqz_next : 1'b0;
    (* max_fanout = 32 *) wire state_we_i = start | in_keyx | round_we | accept_we | sqz_we;
    assign state_we = state_we_i;

    // ------------------------------------------------------------------
    // Stream outputs
    // ------------------------------------------------------------------
    // AEAD output is offered while a message block is presented (never
    // depends on out_ready); the transfer happens in the accept cycle.
    wire offer_out = in_wait & ~start & in_valid & ~pad_pend_q & aead & ~in_ad;

    assign out_valid = offer_out | (in_squeeze & ~start);
    assign out_len   = in_squeeze ? 5'd8 : blk_len;
    assign out_last  = in_squeeze ? (sqz_q == 2'd3) : blk_last;
    assign tag_valid = (state_q == S_DONE) & aead & ~start;
    assign busy      = (state_q != S_IDLE) & (state_q != S_DONE);

    // ------------------------------------------------------------------
    // Sequential logic
    // ------------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            state_q     <= S_IDLE;
            phase_q     <= PH_INIT;
            mode_q      <= 2'd0;
            ridx_q      <= 4'd0;
            half_q      <= 1'b0;
            key_pend_q  <= 1'b0;
            dsep_pend_q <= 1'b0;
            pad_pend_q  <= 1'b0;
            pad_ad_q    <= 1'b0;
            sqz_q       <= 2'd0;
        end else if (start) begin
            mode_q      <= mode;
            key_pend_q  <= (mode != 2'd0);
            dsep_pend_q <= (mode != 2'd0);
            pad_pend_q  <= 1'b0;
            pad_ad_q    <= 1'b0;
            sqz_q       <= 2'd0;
            ridx_q      <= 4'd0;
            half_q      <= 1'b0;
            if (mode != 2'd0) begin
                state_q <= S_ROUND;          // initialisation p12 starts next cycle
                phase_q <= PH_INIT;
            end else begin
                state_q <= S_WAIT;           // hash: precomputed init, absorb immediately
                phase_q <= PH_MSG;
            end
        end else begin
            case (state_q)
                S_WAIT: begin
                    if (accept) begin
                        key_pend_q <= 1'b0;
                        if (blk_msg) dsep_pend_q <= 1'b0;
                        pad_pend_q <= blk_last & blk_full;
                        pad_ad_q   <= blk_ad;
                        if (mode_hash)
                            phase_q <= (blk_last & ~blk_full) ? PH_SQZ : PH_MSG;
                        else if (fin)
                            phase_q <= PH_FIN;
                        else
                            phase_q <= blk_ad ? PH_AD : PH_MSG;
                        if (MERGE && !SPLIT) begin
                            ridx_q <= first_idx + 4'd1;   // first round done in this cycle
                            half_q <= 1'b0;
                        end else if (MERGE && SPLIT) begin
                            ridx_q <= first_idx;          // S-box half done in this cycle
                            half_q <= 1'b1;
                        end else begin
                            ridx_q <= first_idx;          // rounds start next cycle
                            half_q <= 1'b0;
                        end
                        state_q <= S_ROUND;
                    end
                end

                S_ROUND: begin
                    if (SPLIT) begin
                        half_q <= ~half_q;
                        if (half_q) ridx_q <= ridx_q + 4'd1;
                    end else begin
                        ridx_q <= ridx_q + 4'd1;
                    end
                    if (round_exit) begin
                        case (phase_q)
                            PH_FIN:  state_q <= S_KEYX;
                            PH_SQZ:  state_q <= S_SQUEEZE;
                            default: state_q <= S_WAIT;
                        endcase
                    end
                end

                S_KEYX: state_q <= S_DONE;

                S_SQUEEZE: begin
                    if (out_ready) begin
                        if (sqz_q == 2'd3) begin
                            state_q <= S_DONE;
                        end else begin
                            sqz_q <= sqz_q + 2'd1;
                            if (MERGE && !SPLIT) begin
                                ridx_q <= 4'd1;
                                half_q <= 1'b0;
                            end else if (MERGE && SPLIT) begin
                                ridx_q <= 4'd0;
                                half_q <= 1'b1;
                            end else begin
                                ridx_q <= 4'd0;
                                half_q <= 1'b0;
                            end
                            state_q <= S_ROUND;      // phase stays PH_SQZ
                        end
                    end
                end

                default: ;   // S_IDLE, S_DONE: wait for start
            endcase
        end
    end
endmodule
