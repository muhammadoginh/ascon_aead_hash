`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company:
// Engineer:
//
// Create Date: 10/12/2026 05:00:00 PM
// Design Name:
// Module Name: tb_ascon_aead_hash_axi
// Project Name:
// Target Devices:
// Tool Versions:
// Description:
// register-level test of the AXI4-Lite wrapper
//   1. Hash256("aaaaa")                     against the NIST-compliant model
//   2. AEAD128 encrypt "aaaa", zero key/nonce, then decrypt the result
//   3. one multi-block vector with AD through the register interface
//   4. INPUT_META length check raises STATUS.error
//
// Dependencies:
//
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
//
//////////////////////////////////////////////////////////////////////////////////
// ============================================================================

// ============================================================================
module tb_ascon_aead_hash_axi();
    parameter integer SPLIT_ROUND  = 0;
    parameter integer MERGE_ABSORB = 0;

    `include "tb_vectors.svh"

    logic clk = 1'b0;
    logic resetn = 1'b0;
    always #5 clk = ~clk;

    logic [11:0] awaddr = '0;  logic awvalid = 1'b0;  wire awready;
    logic [31:0] wdata  = '0;  logic [3:0] wstrb = '0; logic wvalid = 1'b0; wire wready;
    wire  [1:0]  bresp;        wire bvalid;            logic bready = 1'b0;
    logic [11:0] araddr = '0;  logic arvalid = 1'b0;  wire arready;
    wire  [31:0] rdata;        wire [1:0] rresp;       wire rvalid; logic rready = 1'b0;

    ascon_aead_hash_axi #(.SPLIT_ROUND(SPLIT_ROUND), .MERGE_ABSORB(MERGE_ABSORB)) dut (
        .s_axi_aclk(clk), .s_axi_aresetn(resetn),
        .s_axi_awaddr(awaddr), .s_axi_awvalid(awvalid), .s_axi_awready(awready),
        .s_axi_wdata(wdata), .s_axi_wstrb(wstrb), .s_axi_wvalid(wvalid), .s_axi_wready(wready),
        .s_axi_bresp(bresp), .s_axi_bvalid(bvalid), .s_axi_bready(bready),
        .s_axi_araddr(araddr), .s_axi_arvalid(arvalid), .s_axi_arready(arready),
        .s_axi_rdata(rdata), .s_axi_rresp(rresp), .s_axi_rvalid(rvalid), .s_axi_rready(rready)
    );

    int errors = 0;

    localparam [11:0] CONTROL = 12'h000, STATUS = 12'h010, KEY0 = 12'h100, NONCE0 = 12'h140,
                      INPUT0 = 12'h200, INPUT_META = 12'h240, OUTPUT0 = 12'h300,
                      OUTPUT_META = 12'h340, OUTPUT_POP = 12'h350, TAG0 = 12'h400, TAG_POP = 12'h440;

    task automatic axi_write(input logic [11:0] addr, input logic [31:0] data);
        @(negedge clk);
        awaddr = addr; awvalid = 1'b1; wdata = data; wstrb = 4'hf; wvalid = 1'b1;
        while (!(awready && wready)) @(negedge clk);
        @(negedge clk);
        awvalid = 1'b0; wvalid = 1'b0; bready = 1'b1;
        while (!bvalid) @(negedge clk);
        if (bresp != 2'b00) begin $display("AXI write error at %h", addr); errors++; end
        @(negedge clk);
        bready = 1'b0;
    endtask

    task automatic axi_read(input logic [11:0] addr, output logic [31:0] data);
        @(negedge clk);
        araddr = addr; arvalid = 1'b1; rready = 1'b1;
        while (!arready) @(negedge clk);
        @(negedge clk);
        arvalid = 1'b0;
        while (!rvalid) @(negedge clk);
        data = rdata;
        if (rresp != 2'b00) begin $display("AXI read error at %h", addr); errors++; end
        @(negedge clk);
        rready = 1'b0;
    endtask

    task automatic wait_status(input int bit_idx);
        logic [31:0] st;
        do axi_read(STATUS, st); while (!st[bit_idx]);
    endtask

    task automatic write128(input logic [11:0] base, input logic [127:0] v);
        axi_write(base,          v[31:0]);
        axi_write(base + 12'h10, v[63:32]);
        axi_write(base + 12'h20, v[95:64]);
        axi_write(base + 12'h30, v[127:96]);
    endtask

    task automatic read128(input logic [11:0] base, output logic [127:0] v);
        logic [31:0] w0, w1, w2, w3;
        axi_read(base,          w0);
        axi_read(base + 12'h10, w1);
        axi_read(base + 12'h20, w2);
        axi_read(base + 12'h30, w3);
        v = {w3, w2, w1, w0};
    endtask

    task automatic push(input logic [127:0] blk, input int len, input bit last, input bit ad);
        write128(INPUT0, blk);
        axi_write(INPUT_META, 32'h8000_0000 | (ad << 9) | (last << 8) | len[4:0]);
    endtask

    task automatic pop(output logic [127:0] blk, output int len, output bit last);
        logic [31:0] meta;
        wait_status(8);
        read128(OUTPUT0, blk);
        axi_read(OUTPUT_META, meta);
        len  = meta[4:0];
        last = meta[14];
        axi_write(OUTPUT_POP, 32'h1);
    endtask

    task automatic read_tag(output logic [127:0] t);
        wait_status(10);
        read128(TAG0, t);
        axi_write(TAG_POP, 32'h1);
    endtask

    task automatic check128(input string what, input logic [127:0] got, input logic [127:0] exp);
        if (got !== exp) begin $display("%s FAIL: got %h exp %h", what, got, exp); errors++; end
        else $display("%s PASS", what);
    endtask

    logic [31:0]  st;
    logic [127:0] blk, tg;
    logic [255:0] digest;
    logic [511:0] got_ct;
    int           len, off, blen;
    bit           last;

    initial begin
        load_vectors();
        repeat (5) @(negedge clk);
        resetn = 1'b1;

        // ---- 1. hash "aaaaa" ------------------------------------------------
        axi_write(CONTROL, 32'h2);                       // soft reset
        axi_write(CONTROL, 32'h1);                       // start, mode hash
        push({64'd0, 64'h0000_0061_6161_6161}, 5, 1'b1, 1'b0);
        for (int k = 0; k < 4; k++) begin
            pop(blk, len, last);
            digest[64*k +: 64] = blk[63:0];
            if (len != 8 || last != (k == 3)) begin $display("hash meta error k=%0d", k); errors++; end
        end
        if (digest !== KAT_HASH_AAAAA) begin $display("AXI HASH FAIL: %h", digest); errors++; end
        else $display("AXI HASH PASS");
        axi_read(STATUS, st);
        if (st[1]) begin $display("busy still set after hash"); errors++; end

        // ---- 2. encrypt "aaaa" with zero key / nonce ------------------------
        write128(KEY0, '0);
        write128(NONCE0, '0);
        axi_write(CONTROL, 32'h5);                       // start, encrypt
        wait_status(5);
        push(128'h6161_6161, 4, 1'b1, 1'b0);
        pop(blk, len, last);
        if (len != 4 || !last) begin $display("encrypt meta error"); errors++; end
        check128("AXI ENCRYPT CT ", blk[31:0], KAT_ENC_AAAA_CT);
        read_tag(tg);
        check128("AXI ENCRYPT TAG", tg, KAT_ENC_AAAA_TAG);

        // ---- 3. decrypt it back --------------------------------------------
        axi_write(CONTROL, 32'h9);                       // start, decrypt
        wait_status(5);
        push({96'd0, KAT_ENC_AAAA_CT}, 4, 1'b1, 1'b0);
        pop(blk, len, last);
        check128("AXI DECRYPT PT ", blk[31:0], 32'h6161_6161);
        read_tag(tg);
        check128("AXI DECRYPT TAG", tg, KAT_ENC_AAAA_TAG);

        // ---- 4. first vector with AD and a multi-block message ------------
        for (int i = 0; i < N_AEAD; i++) begin
            if (aead_adlen[i] > 16 && aead_ptlen[i] > 16 && aead_ptlen[i] % 16 != 0) begin
                write128(KEY0, aead_key[i]);
                write128(NONCE0, aead_nonce[i]);
                axi_write(CONTROL, 32'h15);              // start, encrypt, has-AD
                off = 0;
                while (off < aead_adlen[i]) begin
                    blen = (aead_adlen[i] - off > 16) ? 16 : (aead_adlen[i] - off);
                    wait_status(4);
                    push(aead_ad[i][8*off +: 128], blen, off + blen == aead_adlen[i], 1'b1);
                    off += blen;
                end
                off = 0; got_ct = '0;
                while (off < aead_ptlen[i]) begin
                    blen = (aead_ptlen[i] - off > 16) ? 16 : (aead_ptlen[i] - off);
                    wait_status(5);
                    push(aead_pt[i][8*off +: 128], blen, off + blen == aead_ptlen[i], 1'b0);
                    pop(blk, len, last);
                    got_ct[8*off +: 128] = blk;
                    off += blen;
                end
                if ((got_ct & ((512'h1 << (8*aead_ptlen[i])) - 1)) !== (aead_ct[i] & ((512'h1 << (8*aead_ptlen[i])) - 1))) begin
                    $display("AXI VECTOR %0d CT FAIL", i); errors++;
                end else $display("AXI VECTOR %0d CT PASS (ad %0d, pt %0d)", i, aead_adlen[i], aead_ptlen[i]);
                read_tag(tg);
                check128("AXI VECTOR TAG ", tg, aead_tag[i]);
                break;
            end
        end

        // ---- 5. invalid length sets the error flag ----------------------
        axi_write(CONTROL, 32'h5);
        axi_write(INPUT_META, 32'h8000_0011);            // 17 bytes in AEAD mode
        axi_read(STATUS, st);
        if (!st[11]) begin $display("error flag not set for bad length"); errors++; end
        else $display("AXI ERROR FLAG PASS");
        axi_write(CONTROL, 32'h2);
        axi_read(STATUS, st);
        if (st[11]) begin $display("error flag not cleared by soft reset"); errors++; end

        if (errors == 0) $display("ALL AXI TESTS PASSED (SPLIT_ROUND=%0d MERGE_ABSORB=%0d)", SPLIT_ROUND, MERGE_ABSORB);
        else $display("FAILED: %0d AXI errors (SPLIT_ROUND=%0d MERGE_ABSORB=%0d)", errors, SPLIT_ROUND, MERGE_ABSORB);
        $finish;
    end
endmodule
