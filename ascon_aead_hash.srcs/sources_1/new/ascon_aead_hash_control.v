`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company:
// Engineer:
//
// Create Date: 10/12/2026 05:00:00 PM
// Design Name:
// Module Name: ascon_aead_hash_control
// Project Name:
// Target Devices:
// Tool Versions:
// Description:
// one-hot FSM, lazy last round
//
// Schedule (1 round per cycle):
//   start -> LOAD (1 cycle: IV||K||N or HASH_PARK) -> rounds
//   AEAD init             : 11 round cycles, round 11 pending
//   AEAD block (AD / msg) : 8 cycles  (p8)   - the pending round of the
//   final block -> tag    : 12 cycles (p12)    previous permutation and the
//   hash block            : 12 cycles (p12)    block injection share a cycle
//   hash squeeze word     : 12 cycles between words
// A block is accepted when its permutation can start: in WAIT (last round
// pending) or in the last round cycle of the running permutation.  The C/P
// output of a message block is offered in the accept cycle, so blocks are
// only accepted while out_ready is high (no stall logic).  The acceptance
// decision is one LUT from registered ready flags and the in_valid / in_ad /
// out_ready inputs.  Protocol notes: in_valid must be low in the start
// cycle, and in_ad must be low in hash mode (both guaranteed by the AXI
// wrapper).
//
// Dependencies: 
//
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
//
//////////////////////////////////////////////////////////////////////////////////


module ascon_aead_hash_control #(
    parameter integer SPLIT_ROUND  = 0,   // unused in v3
    parameter integer MERGE_ABSORB = 1    // unused in v3
) (
    input  wire         clk,
    input  wire         rst,
    // ---- command ----------------------------------------------------------
    input  wire         start,
    input  wire [1:0]   mode,           // 0 hash, 1 encrypt, 2 decrypt (sampled with start)
    output wire         busy,
    output wire         tag_valid,
    // ---- input stream -----------------------------------------------------
    input  wire         in_valid,
    input  wire [4:0]   in_len,
    input  wire         in_last,
    input  wire         in_ad,
    output wire         in_ready,
    output wire         in_ready_ad,
    output wire         in_ready_msg,
    // ---- output stream ----------------------------------------------------
    output wire         out_valid,
    output wire [4:0]   out_len,
    output wire         out_last,
    input  wire         out_ready,
    // ---- datapath control -------------------------------------------------
    output wire         we,
    output wire         load_hash,
    output wire         ldi,
    output wire         acc,
    output wire         kinit,
    output wire         kfin,
    output wire         dsep,
    output wire         decm,
    output wire         sqz_sel,
    output wire [15:0]  bmr,
    output wire [15:0]  pbr,
    output reg  [7:0]   rc_q
);
    // ---- registers --------------------------------------------------------
    reg st_load, st_wait, st_round, st_sqz, st_done;   // one-hot (idle = none)
    reg ph_init, ph_ad, ph_msg, ph_fin, ph_sqz;        // what follows the running permutation
    reg hash_q, dec_q, aead_q;
    reg [3:0] ridx_q;                                   // round computed from state_q this cycle
    reg lastr_q;                                        // ridx_q == 11 (last round)
    reg finl_q;                                         // last round of the final permutation (eager)
    reg rdy_pad_q, rdy_ad_q, rdy_msg_q;                 // registered acceptance windows
    reg kinit_pend, dsep_pend;                          // XORs still to be merged into an absorb
    reg pad_pend, pad_ad, padfin_q;                     // internal padding block pending (AD? final?)
    reg pb8_ok_q;                                       // ~pad_pend & aead: a 16-byte block may pad at byte 8
    reg [1:0] sqz_q;

    // ---- block presented (internal padding block has priority) --------------
    wire       full16   = (in_len == 5'd16);
    wire       full8    = (in_len == 5'd8);
    wire       blk_ad   = pad_pend ? pad_ad : in_ad;
    wire       blk_last = pad_pend | in_last;
    wire [4:0] blk_len  = pad_pend ? 5'd0 : in_len;
    wire       blk_msg  = ~blk_ad;
    wire       full     = ~pad_pend & (hash_q ? full8 : full16);
    wire       fin_in   = aead_q & ~in_ad & in_last & ~full16;       // presented stream block is final
    wire       fin      = pad_pend ? padfin_q : fin_in;
    wire       emits    = aead_q & blk_msg & ~pad_pend;             // C/P output exists

    assign in_ready_ad  = rdy_ad_q  & out_ready;
    assign in_ready_msg = rdy_msg_q & out_ready;
    assign in_ready     = in_ad ? in_ready_ad : in_ready_msg;
    // accept = rdy_pad | (in_valid & out_ready & (in_ad ? rdy_ad : rdy_msg)): six inputs,
    // one LUT; inferred (not instantiated) so that synthesis can replicate it for fan-out
    (* max_fanout = 24 *) wire accept = rdy_pad_q | (in_valid & out_ready & (in_ad ? rdy_ad_q : rdy_msg_q));

    genvar j;
    generate
        for (j = 0; j < 16; j = j + 1) begin : g_byte
            assign bmr[j] = ~pad_pend & (in_len > j);
            if (j == 0) begin : g_pb0
                assign pbr[j] = pad_pend | (in_len == 5'd0);
            end else if (j == 8) begin : g_pb8
                assign pbr[j] = pb8_ok_q & (in_len == 5'd8);
            end else begin : g_pbn
                assign pbr[j] = ~pad_pend & (in_len == j[4:0]);
            end
        end
    endgenerate

    // ---- datapath control -------------------------------------------------
    wire       sqz_go = st_sqz & out_ready & (sqz_q != 2'd3);        // next digest word
    wire [3:0] first  = (hash_q | fin) ? 4'd0 : 4'd4;
    wire [3:0] ridx_d = st_load ? (hash_q ? 4'd11 : 4'd0) :
                        accept  ? first :
                        sqz_go  ? 4'd0 :
                        (st_round & ~lastr_q) ? ridx_q + 4'd1 : ridx_q;
    (* max_fanout = 64 *) wire ldi_i       = st_load & aead_q;
    (* max_fanout = 64 *) wire load_hash_i = st_load & hash_q;
    (* max_fanout = 64 *) wire we_i        = st_load | (st_round & ~lastr_q) | accept | sqz_go | finl_q;
    (* max_fanout = 32 *) wire kinit_i     = (accept & kinit_pend) | finl_q;   // final round: S3,S4 ^= K -> tag
    // kfin = accept & fin in two LUT levels from the inputs (a final block is a
    // message block, so its acceptance only involves the message window)
    wire u_msg = in_valid & out_ready & rdy_msg_q & ~in_ad & aead_q & in_last;
    (* max_fanout = 32 *) wire kfin_i      = (pad_pend & rdy_pad_q & padfin_q) | (~pad_pend & u_msg & ~full16);
    assign acc       = accept;
    assign ldi       = ldi_i;
    assign load_hash = load_hash_i;
    assign we        = we_i;
    assign kinit     = kinit_i;
    assign kfin      = kfin_i;
    assign dsep      = accept & dsep_pend & blk_msg;
    assign decm      = dec_q & ~in_ad;            // internal pad block has no valid bytes, so pad_ad is irrelevant
    assign sqz_sel   = st_sqz;

    // ---- stream outputs ---------------------------------------------------
    assign out_valid = (accept & emits) | st_sqz;
    assign out_len   = st_sqz ? 5'd8 : blk_len;
    assign out_last  = st_sqz ? (sqz_q == 2'd3) : blk_last;
    assign tag_valid = st_done & aead_q & ~start;
    assign busy      = st_load | st_wait | st_round | st_sqz;

    // acceptance window of the next cycle: WAIT, the two last round cycles of
    // a permutation that may be followed by a block, or the hash load cycle
    wire ph_data  = ph_init | ph_ad | ph_msg;
    wire near_end = st_round & ph_data & (ridx_q[3:1] == 3'b101);   // ridx 10 or 11
    wire ready_d  = ~accept & (st_wait | near_end | (st_load & hash_q));
    wire pad_d    = accept ? (blk_last & full) : pad_pend;

    // ---- sequential logic -------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            {st_load, st_wait, st_round, st_sqz, st_done} <= 5'b0;
            {ph_init, ph_ad, ph_msg, ph_fin, ph_sqz} <= 5'b0;
            hash_q <= 1'b0; dec_q <= 1'b0; aead_q <= 1'b0;
            ridx_q <= 4'd0; rc_q <= 8'hf0; lastr_q <= 1'b0; finl_q <= 1'b0;
            rdy_pad_q <= 1'b0; rdy_ad_q <= 1'b0; rdy_msg_q <= 1'b0;
            kinit_pend <= 1'b0; dsep_pend <= 1'b0; pad_pend <= 1'b0; pad_ad <= 1'b0; padfin_q <= 1'b0;
            pb8_ok_q <= 1'b0; sqz_q <= 2'd0;
        end else if (start) begin
            hash_q <= (mode == 2'd0); dec_q <= (mode == 2'd2); aead_q <= (mode != 2'd0);
            kinit_pend <= (mode != 2'd0); dsep_pend <= (mode != 2'd0);
            pad_pend <= 1'b0; pad_ad <= 1'b0; padfin_q <= 1'b0; pb8_ok_q <= (mode != 2'd0); sqz_q <= 2'd0;
            {st_load, st_wait, st_round, st_sqz, st_done} <= 5'b10000;
            {ph_init, ph_ad, ph_msg, ph_fin, ph_sqz} <= (mode != 2'd0) ? 5'b10000 : 5'b00100;
            ridx_q <= 4'd0; rc_q <= 8'hf0; lastr_q <= 1'b0; finl_q <= 1'b0;
            rdy_pad_q <= 1'b0; rdy_ad_q <= 1'b0; rdy_msg_q <= 1'b0;
        end else begin
            ridx_q    <= ridx_d;
            rc_q      <= {~ridx_d, ridx_d};
            lastr_q   <= st_round & (ridx_q == 4'd10);
            finl_q    <= st_round & (ridx_q == 4'd10) & ph_fin;
            rdy_pad_q <= ready_d & pad_d;
            rdy_ad_q  <= ready_d & ~pad_d & aead_q;
            rdy_msg_q <= ready_d & ~pad_d;
            pb8_ok_q  <= ~pad_d & aead_q;

            if (st_load) begin
                st_load <= 1'b0;
                if (hash_q) st_wait  <= 1'b1;          // parked, round 11 pending
                else        st_round <= 1'b1;          // init permutation
            end else if (accept) begin
                kinit_pend <= 1'b0;
                if (blk_msg) dsep_pend <= 1'b0;
                pad_pend <= blk_last & full; pad_ad <= blk_ad;
                padfin_q <= blk_last & full & aead_q & blk_msg;     // the pad block will be the final block
                if (hash_q) begin
                    {ph_init, ph_ad, ph_msg, ph_fin, ph_sqz} <= (blk_last & ~full) ? 5'b00001 : 5'b00100;
                end else begin
                    {ph_init, ph_ad, ph_msg, ph_fin, ph_sqz} <= fin ? 5'b00010 : (blk_ad ? 5'b01000 : 5'b00100);
                end
                st_wait <= 1'b0; st_round <= 1'b1;
            end else if (st_round & lastr_q) begin
                // permutation reached its last round without a next block
                st_round <= 1'b0;
                if (ph_fin)      st_done <= 1'b1;      // written eagerly (finl_q): tag = {S4, S3}
                else if (ph_sqz) st_sqz  <= 1'b1;      // parked: out_data = S0 of the pending round
                else             st_wait <= 1'b1;      // parked
            end else if (st_sqz & out_ready) begin
                st_sqz <= 1'b0;
                if (sqz_q == 2'd3) st_done <= 1'b1;
                else begin sqz_q <= sqz_q + 2'd1; st_round <= 1'b1; end
            end
        end
    end
endmodule
