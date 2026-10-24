`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 10/24/2026 11:04:29 AM
// Design Name: 
// Module Name: ascon_aead_hash_datapath
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// two LUT levels per cycle
//
//   state_q --[S-box LUT5/6]--[linear layer + injection LUT5]--> state_q
//
// * The S-box of state column i is one LUT5 per output bit; for the eight
//   columns that receive the round constant it is a LUT6 whose sixth input
//   is the registered constant bit rc_q[i] (p_C costs no logic level).
// * Every state write is   y = m ? d : (pL(pS(state)) ^ d)   in one LUT5 per
//   bit, where d is the injection word prepared outside the loop (block,
//   key, domain separation, or the AEAD init vector) and m selects
//   replacement (decrypt rate bytes, init load).
// * The last round of a permutation stays PENDING while the core waits for
//   the next block (or squeezes), so a block that arrives later is injected
//   through the same path together with that round; hashing starts from the
//   constant p^11(IV_H) with round 11 pending (HASH_PARK, loaded through the
//   flip-flop set/reset pins).  The final permutation completes eagerly with
//   the key XOR merged into its last round, so the tag is {S4, S3} itself.
// * The C/P output recomputes the linear layer from the S-box outputs
//   (one LUT6 per bit: 3 S-box bits, in_data bit, byte valid, squeeze select).
// * Dual-output LUT6_2 cells hold two S-box outputs of a column (the five
//   outputs share their five inputs) and two S0 injection bits of a byte.
// Byte order: block byte 0 in bits [7:0]; S0 = bytes 0..7, S1 = bytes 8..15.
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module ascon_aead_hash_datapath #(
    parameter integer SPLIT_ROUND  = 0,   // unused in v3 (kept for compatibility)
    parameter integer MERGE_ABSORB = 1    // unused in v3
) (
    input  wire         clk,
    input  wire         rst,            // unused: the state is always loaded before use
    // ---- control ---------------------------------------------------------
    input  wire         we,             // state <= y
    input  wire         load_hash,      // state <= HASH_PARK (priority over we)
    input  wire         ldi,            // AEAD init load: y = d = IV || K || N
    input  wire         acc,            // a block is injected this cycle
    input  wire         kinit,          // K -> S3,S4 (after init, and with the final round)
    input  wire         kfin,           // K -> S2,S3 (final block)
    input  wire         dsep,           // domain separation -> S4[63]
    input  wire         decm,           // decrypt message block: ciphertext replaces the rate
    input  wire         sqz_sel,        // out_data = digest word S0
    input  wire [15:0]  bmr,            // valid bytes of the presented block
    input  wire [15:0]  pbr,            // 0x01 pad byte position of the presented block
    input  wire [7:0]   rc_q,           // constant of the round computed this cycle
    // ---- data ------------------------------------------------------------
    input  wire [127:0] in_data,
    input  wire [127:0] key,
    input  wire [127:0] nonce,
    output wire [127:0] out_data,       // C / P of the accepted block, or {0, S0}
    output wire [127:0] tag             // {S4, S3} after the final permutation
);
    localparam [63:0] AEAD128_IV = 64'h00001000808c0001;
    // p^11(IV_H): round 11 pending (its constant comes from rc_q while parked)
    localparam [63:0] HASH_PARK_S0 = 64'h338537aea20f6ff3;
    localparam [63:0] HASH_PARK_S1 = 64'h6d22176ebb87252a;
    localparam [63:0] HASH_PARK_S2 = 64'h645870f515740001;
    localparam [63:0] HASH_PARK_S3 = 64'h63870fc13051c65f;
    localparam [63:0] HASH_PARK_S4 = 64'hb4b3d5d3ae916c43;

    // ---- truth tables ------------------------------------------------------
    // S-box output k of the column {x4..x0} = {I4..I0}; with_rc: x2 ^= I5
    function [63:0] sbox_init(input integer k, input integer with_rc);
        integer v; reg [5:0] vb; reg [4:0] o; reg x0, x1, x2, x3, x4, t0, t1, t2, t3, t4;
        begin
            sbox_init = 64'd0;
            for (v = 0; v < 64; v = v + 1) begin
                vb = v[5:0];
                x0 = vb[0]; x1 = vb[1]; x2 = vb[2] ^ (with_rc != 0 && vb[5]); x3 = vb[3]; x4 = vb[4];
                x0 = x0 ^ x4; x4 = x4 ^ x3; x2 = x2 ^ x1;
                t0 = ~x0 & x1; t1 = ~x1 & x2; t2 = ~x2 & x3; t3 = ~x3 & x4; t4 = ~x4 & x0;
                x0 = x0 ^ t1; x1 = x1 ^ t2; x2 = x2 ^ t3; x3 = x3 ^ t4; x4 = x4 ^ t0;
                x1 = x1 ^ x0; x0 = x0 ^ x4; x3 = x3 ^ x2; x2 = ~x2;
                o = {x4, x3, x2, x1, x0};
                sbox_init[v] = o[k];
            end
        end
    endfunction
    // linear layer + injection: O = I4 ? I3 : (I0 ^ I1 ^ I2 ^ I3)
    function [31:0] lin_init(input integer dummy);
        integer v; reg [4:0] vb;
        begin
            lin_init = 32'd0;
            for (v = 0; v < 32; v = v + 1) begin
                vb = v[4:0];
                lin_init[v] = vb[4] ? vb[3] : (vb[0] ^ vb[1] ^ vb[2] ^ vb[3]);
            end
        end
    endfunction
    localparam [63:0] SB0 = sbox_init(0, 0), SB1 = sbox_init(1, 0), SB2 = sbox_init(2, 0),
                      SB3 = sbox_init(3, 0), SB4 = sbox_init(4, 0);
    localparam [63:0] SR0 = sbox_init(0, 1), SR1 = sbox_init(1, 1), SR2 = sbox_init(2, 1),
                      SR3 = sbox_init(3, 1), SR4 = sbox_init(4, 1);
    localparam [31:0] LIN = lin_init(0);

    reg  [319:0] state_q;
    wire [63:0]  s0 = state_q[319:256];
    wire [63:0]  s1 = state_q[255:192];
    wire [63:0]  s2 = state_q[191:128];
    wire [63:0]  s3 = state_q[127:64];
    wire [63:0]  s4 = state_q[63:0];
    wire [63:0]  k_lo = key[63:0];
    wire [63:0]  k_hi = key[127:64];
    wire [63:0]  n_lo = nonce[63:0];
    wire [63:0]  n_hi = nonce[127:64];

    // ---- byte-level descriptors of the presented block ---------------------
    wire [15:0]  mr = {16{ldi}} | ({16{decm & acc}} & bmr);   // replace rate byte (decrypt)
    wire [127:0] bmx, pbx, mrx;
    genvar j;
    generate
        for (j = 0; j < 16; j = j + 1) begin : g_byte
            assign bmx[8*j +: 8] = {8{bmr[j]}};
            assign mrx[8*j +: 8] = {8{mr[j]}};
            assign pbx[8*j +: 8] = {7'd0, pbr[j]};
        end
    endgenerate

    // ---- injection words (one LUT level after acc) -------------------------
    wire [127:0] blk = {128{acc}} & ((in_data & bmx) | pbx);
    // S0 word: d0 = ldi ? IV : acc & ((x & bm) | pb) -- bits 1..6 of each byte in pairs
    // (inputs ldi, acc, bm_j, x_a, x_b; the IV bit is a constant of the table)
    function [31:0] d0_init(input integer ivbit, input integer xsel);  // xsel: 3 -> I3, 4 -> I4
        integer v; reg [4:0] vb; reg x;
        begin
            d0_init = 32'd0;
            for (v = 0; v < 32; v = v + 1) begin
                vb = v[4:0]; x = (xsel == 3) ? vb[3] : vb[4];
                d0_init[v] = vb[0] ? (ivbit != 0) : (vb[1] & vb[2] & x);   // I0 = ldi, I1 = acc, I2 = bm
            end
        end
    endfunction
    wire [63:0] d0;
    generate
        for (j = 0; j < 8; j = j + 1) begin : g_d0
            // bit 0 (pad position) and bit 7: single LUTs
            assign d0[8*j]   = ldi ? AEAD128_IV[8*j]   : blk[8*j];
            assign d0[8*j+7] = ldi ? AEAD128_IV[8*j+7] : blk[8*j+7];
            ascon_lut6_2 #(.INIT({d0_init(AEAD128_IV[8*j+2], 4), d0_init(AEAD128_IV[8*j+1], 3)})) u12
                (.I0(ldi), .I1(acc), .I2(bmr[j]), .I3(in_data[8*j+1]), .I4(in_data[8*j+2]), .I5(1'b1), .O5(d0[8*j+1]), .O6(d0[8*j+2]));
            ascon_lut6_2 #(.INIT({d0_init(AEAD128_IV[8*j+4], 4), d0_init(AEAD128_IV[8*j+3], 3)})) u34
                (.I0(ldi), .I1(acc), .I2(bmr[j]), .I3(in_data[8*j+3]), .I4(in_data[8*j+4]), .I5(1'b1), .O5(d0[8*j+3]), .O6(d0[8*j+4]));
            ascon_lut6_2 #(.INIT({d0_init(AEAD128_IV[8*j+6], 4), d0_init(AEAD128_IV[8*j+5], 3)})) u56
                (.I0(ldi), .I1(acc), .I2(bmr[j]), .I3(in_data[8*j+5]), .I4(in_data[8*j+6]), .I5(1'b1), .O5(d0[8*j+5]), .O6(d0[8*j+6]));
        end
    endgenerate
    wire [63:0]  d1 = ldi ? k_lo       : blk[127:64];
    wire [63:0]  d2 = ldi ? k_hi       : ({64{kfin}} & k_lo);
    wire [63:0]  d3 = ldi ? n_lo       : (({64{kfin}}  & k_hi) ^ ({64{kinit}} & k_lo));
    wire [63:0]  d4 = ldi ? n_hi       : (({64{kinit}} & k_hi) ^ {dsep, 63'd0});
    wire [63:0]  m0 = mrx[63:0];
    wire [63:0]  m1 = mrx[127:64];
    wire [63:0]  m2 = {64{ldi}}, m3 = {64{ldi}}, m4 = {64{ldi}};

    // ---- S-box layer: 320 LUTs (LUT6 with the round constant on columns 0..7)
    wire [63:0] v0, v1, v2, v3, v4;
    genvar i;
    generate
        for (i = 0; i < 64; i = i + 1) begin : g_sbox
            if (i < 8) begin : g_rc
                ascon_lut6 #(.INIT(SR0)) u0 (.I0(s0[i]), .I1(s1[i]), .I2(s2[i]), .I3(s3[i]), .I4(s4[i]), .I5(rc_q[i]), .O(v0[i]));
                ascon_lut6 #(.INIT(SR1)) u1 (.I0(s0[i]), .I1(s1[i]), .I2(s2[i]), .I3(s3[i]), .I4(s4[i]), .I5(rc_q[i]), .O(v1[i]));
                ascon_lut6 #(.INIT(SR2)) u2 (.I0(s0[i]), .I1(s1[i]), .I2(s2[i]), .I3(s3[i]), .I4(s4[i]), .I5(rc_q[i]), .O(v2[i]));
                ascon_lut6 #(.INIT(SR3)) u3 (.I0(s0[i]), .I1(s1[i]), .I2(s2[i]), .I3(s3[i]), .I4(s4[i]), .I5(rc_q[i]), .O(v3[i]));
                ascon_lut6 #(.INIT(SR4)) u4 (.I0(s0[i]), .I1(s1[i]), .I2(s2[i]), .I3(s3[i]), .I4(s4[i]), .I5(rc_q[i]), .O(v4[i]));
            end else begin : g_plain
                // two S-box outputs per dual-output LUT (5 shared inputs, I5 = 1)
                ascon_lut6_2 #(.INIT({SB1[31:0], SB0[31:0]})) u01 (.I0(s0[i]), .I1(s1[i]), .I2(s2[i]), .I3(s3[i]), .I4(s4[i]), .I5(1'b1), .O5(v0[i]), .O6(v1[i]));
                ascon_lut6_2 #(.INIT({SB3[31:0], SB2[31:0]})) u23 (.I0(s0[i]), .I1(s1[i]), .I2(s2[i]), .I3(s3[i]), .I4(s4[i]), .I5(1'b1), .O5(v2[i]), .O6(v3[i]));
                ascon_lut5   #(.INIT(SB4[31:0]))              u4  (.I0(s0[i]), .I1(s1[i]), .I2(s2[i]), .I3(s3[i]), .I4(s4[i]), .O(v4[i]));
            end
        end
    endgenerate

    // ---- linear layer + injection: 320 LUT5 -------------------------------
    // y_k[i] = m ? d : v_k[i] ^ v_k[(i+r1)%64] ^ v_k[(i+r2)%64]   (rotr by r1, r2)
    wire [63:0] y0, y1, y2, y3, y4;
    generate
        for (i = 0; i < 64; i = i + 1) begin : g_lin
            ascon_lut5 #(.INIT(LIN)) l0 (.I0(v0[i]), .I1(v0[(i+19)%64]), .I2(v0[(i+28)%64]), .I3(d0[i]), .I4(m0[i]), .O(y0[i]));
            ascon_lut5 #(.INIT(LIN)) l1 (.I0(v1[i]), .I1(v1[(i+61)%64]), .I2(v1[(i+39)%64]), .I3(d1[i]), .I4(m1[i]), .O(y1[i]));
            ascon_lut5 #(.INIT(LIN)) l2 (.I0(v2[i]), .I1(v2[(i+1)%64]),  .I2(v2[(i+6)%64]),  .I3(d2[i]), .I4(m2[i]), .O(y2[i]));
            ascon_lut5 #(.INIT(LIN)) l3 (.I0(v3[i]), .I1(v3[(i+10)%64]), .I2(v3[(i+17)%64]), .I3(d3[i]), .I4(m3[i]), .O(y3[i]));
            ascon_lut5 #(.INIT(LIN)) l4 (.I0(v4[i]), .I1(v4[(i+7)%64]),  .I2(v4[(i+41)%64]), .I3(d4[i]), .I4(m4[i]), .O(y4[i]));
        end
    endgenerate

    // ---- state register (no reset: loaded before every use) ---------------
    always @(posedge clk) begin
        if (load_hash)  state_q <= {HASH_PARK_S0, HASH_PARK_S1, HASH_PARK_S2, HASH_PARK_S3, HASH_PARK_S4};
        else if (we)    state_q <= {y0, y1, y2, y3, y4};
    end

    // ---- outputs: linear layer recomputed from the S-box outputs ----------
    wire [63:0] l0, l1;
    generate
        for (i = 0; i < 64; i = i + 1) begin : g_out
            assign l0[i] = v0[i] ^ v0[(i+19)%64] ^ v0[(i+28)%64];
            assign l1[i] = v1[i] ^ v1[(i+61)%64] ^ v1[(i+39)%64];
        end
    endgenerate
    wire [127:0] msg_out = ({l1, l0} ^ in_data) & bmx;     // C = S ^ P  /  P = S ^ C (valid bytes)
    assign out_data = sqz_sel ? {64'd0, l0} : msg_out;
    assign tag      = {s4, s3};
endmodule
