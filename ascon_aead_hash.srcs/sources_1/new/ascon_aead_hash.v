`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company:
// Engineer:
//
// Create Date: 10/12/2026 05:00:00 PM
// Design Name:
// Module Name: tb_ascon_aead_hash
// Project Name:
// Target Devices:
// Tool Versions:
// Description:
// unified Ascon-AEAD128 / Ascon-Hash256 core,
// lazy-last-round control, two LUT levels per cycle (see control / datapath).
//
// Dependencies: 
//
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
//
//////////////////////////////////////////////////////////////////////////////////


module ascon_aead_hash #(
    parameter integer SPLIT_ROUND  = 0,   // accepted for compatibility, unused
    parameter integer MERGE_ABSORB = 1    // accepted for compatibility, unused
) (
    input  wire         clk,
    input  wire         rst,
    input  wire         start,
    input  wire [1:0]   mode,
    input  wire [127:0] key,
    input  wire [127:0] nonce,
    output wire         busy,
    input  wire         in_valid,
    input  wire [127:0] in_data,
    input  wire [4:0]   in_len,
    input  wire         in_last,
    input  wire         in_ad,
    output wire         in_ready,
    output wire         in_ready_ad,
    output wire         in_ready_msg,
    output wire         out_valid,
    output wire [127:0] out_data,
    output wire [4:0]   out_len,
    output wire         out_last,
    input  wire         out_ready,
    output wire         tag_valid,
    output wire [127:0] tag
);
    wire        we, load_hash, ldi, acc, sqz_sel, kinit, kfin, dsep, decm;
    wire [15:0] bmr, pbr;
    wire [7:0]  rc_q;

    ascon_aead_hash_control u_ctrl (
        .clk(clk), .rst(rst), .start(start), .mode(mode), .busy(busy), .tag_valid(tag_valid),
        .in_valid(in_valid), .in_len(in_len), .in_last(in_last), .in_ad(in_ad),
        .in_ready(in_ready), .in_ready_ad(in_ready_ad), .in_ready_msg(in_ready_msg),
        .out_valid(out_valid), .out_len(out_len), .out_last(out_last), .out_ready(out_ready),
        .we(we), .load_hash(load_hash), .ldi(ldi), .acc(acc), .sqz_sel(sqz_sel),
        .kinit(kinit), .kfin(kfin), .dsep(dsep), .decm(decm), .bmr(bmr), .pbr(pbr), .rc_q(rc_q)
    );

    ascon_aead_hash_datapath u_dp (
        .clk(clk), .rst(rst), .we(we), .load_hash(load_hash), .ldi(ldi), .acc(acc), .sqz_sel(sqz_sel),
        .kinit(kinit), .kfin(kfin), .dsep(dsep), .decm(decm), .bmr(bmr), .pbr(pbr), .rc_q(rc_q),
        .in_data(in_data), .key(key), .nonce(nonce), .out_data(out_data), .tag(tag)
    );
endmodule
