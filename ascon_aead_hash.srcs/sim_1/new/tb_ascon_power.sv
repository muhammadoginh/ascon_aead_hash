`timescale 1ns / 1ps
// ============================================================================
// tb_ascon_power.sv -- switching-activity stimulus for power estimation
//
// Keeps the unified core busy with realistic traffic and no back-pressure:
//   +MODE=aead : Ascon-AEAD128 encryption, 80-byte AD + 4096-byte message
//   +MODE=hash : Ascon-Hash256 of 4096 bytes
//   +MODE=both : one AEAD run followed by one hash run
// repeated +REPEAT=n times (default 3) at a clock period of +PERIOD_PS
// (default 4750 ps).  Used on the post-route functional netlist by
// scripts/power_saif.tcl, which logs a SAIF file and feeds it to report_power.
//
// The DUT is instantiated without parameter overrides so that the same file
// simulates the RTL (defaults SPLIT_ROUND = 0, MERGE_ABSORB = 0) and the
// parameter-less netlist written by write_verilog -mode funcsim.
//
// Deterministic data (byte i): AD = (13*i + 1) mod 256, message = (7*i + 3)
// mod 256, key = 00..0F, nonce = 10..1F.  The printed TAG / DIGEST words are
// checked against the Python model by scripts/power_expected.py.
// ============================================================================
module tb_ascon_power;
    string  mode_str  = "aead";
    int     period_ps = 4750;
    int     repeat_n  = 3;
    real    half      = 2.375;

    logic         clk = 1'b0;
    logic         rst = 1'b1;
    logic         start    = 1'b0;
    logic [1:0]   mode     = 2'd0;
    logic [127:0] key, nonce;
    logic         in_valid = 1'b0;
    logic [127:0] in_data  = '0;
    logic [4:0]   in_len   = '0;
    logic         in_last  = 1'b0;
    logic         in_ad    = 1'b0;
    wire          in_ready, in_ready_ad, in_ready_msg;
    wire          out_valid;
    wire [127:0]  out_data;
    wire [4:0]    out_len;
    wire          out_last;
    logic         out_ready = 1'b1;
    wire          tag_valid;
    wire [127:0]  tag;
    wire          busy;
    longint       cycles = 0;

    ascon_aead_hash dut (
        .clk(clk), .rst(rst), .start(start), .mode(mode), .key(key), .nonce(nonce), .busy(busy),
        .in_valid(in_valid), .in_data(in_data), .in_len(in_len), .in_last(in_last), .in_ad(in_ad),
        .in_ready(in_ready), .in_ready_ad(in_ready_ad), .in_ready_msg(in_ready_msg),
        .out_valid(out_valid), .out_data(out_data), .out_len(out_len), .out_last(out_last),
        .out_ready(out_ready), .tag_valid(tag_valid), .tag(tag)
    );

    always @(posedge clk) if (!rst) cycles <= cycles + 1;

    function automatic logic [127:0] msg_block(input int b);
        logic [127:0] r = '0;
        for (int j = 0; j < 16; j++) r[8*j +: 8] = 8'(((16*b + j) * 7 + 3) & 255);
        return r;
    endfunction

    function automatic logic [127:0] ad_block(input int b);
        logic [127:0] r = '0;
        for (int j = 0; j < 16; j++) r[8*j +: 8] = 8'(((16*b + j) * 13 + 1) & 255);
        return r;
    endfunction

    function automatic logic [127:0] hash_block(input int b);
        logic [127:0] r = '0;
        for (int j = 0; j < 8; j++) r[8*j +: 8] = 8'(((8*b + j) * 7 + 3) & 255);
        return r;
    endfunction

    task automatic do_start(input logic [1:0] m);
        @(negedge clk); mode = m; start = 1'b1;
        @(negedge clk); start = 1'b0;
    endtask

    task automatic send_block(input logic [127:0] data, input int len, input bit last, input bit ad);
        @(negedge clk);
        in_valid = 1'b1; in_data = data; in_len = len[4:0]; in_last = last; in_ad = ad;
        #1;
        while (!in_ready) begin @(negedge clk); #1; end
        @(posedge clk);                       // accepted here
    endtask

    task automatic end_stream();
        @(negedge clk); in_valid = 1'b0; in_last = 1'b0; in_ad = 1'b0; in_len = '0;
    endtask

    task automatic run_aead();
        do_start(2'd1);
        for (int b = 0; b < 5; b++)   send_block(ad_block(b), 16, b == 4, 1'b1);
        for (int b = 0; b < 256; b++) send_block(msg_block(b), 16, b == 255, 1'b0);
        end_stream();
        while (!tag_valid) @(negedge clk);
        $display("TAG=%032x", tag);
    endtask

    task automatic run_hash();
        int k = 0;
        do_start(2'd0);
        for (int b = 0; b < 512; b++) send_block(hash_block(b), 8, b == 511, 1'b0);
        end_stream();
        while (k < 4) begin
            @(negedge clk); #1;
            if (out_valid && out_ready) begin
                $display("DIGEST_WORD%0d=%016x", k, out_data[63:0]);
                k++;
                @(posedge clk);
            end
        end
        while (busy) @(negedge clk);
    endtask

    initial begin
        if (!$value$plusargs("MODE=%s", mode_str))     mode_str  = "aead";
        if (!$value$plusargs("PERIOD_PS=%d", period_ps)) period_ps = 4750;
        if (!$value$plusargs("REPEAT=%d", repeat_n))   repeat_n  = 3;
        half = period_ps / 2000.0;
        for (int i = 0; i < 16; i++) begin
            key[8*i +: 8]   = 8'(i);
            nonce[8*i +: 8] = 8'(16 + i);
        end
        fork
            forever #(half) clk = ~clk;
        join_none
        #250;                                  // longer than the 100 ns GSR of glbl
        @(negedge clk); rst = 1'b0;
        @(negedge clk);
        for (int r = 0; r < repeat_n; r++) begin
            if (mode_str == "aead")      run_aead();
            else if (mode_str == "hash") run_hash();
            else begin run_aead(); run_hash(); end
        end
        repeat (4) @(negedge clk);
        $display("POWER_TB_DONE mode=%s period_ps=%0d repeat=%0d cycles=%0d", mode_str, period_ps, repeat_n, cycles);
        $finish;
    end
endmodule
