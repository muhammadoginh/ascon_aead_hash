`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company:
// Engineer:
//
// Create Date: 10/12/2026 05:00:00 PM
// Design Name:
// Module Name: ascon_aead_hash_axi
// Project Name:
// Target Devices:
// Tool Versions:
// Description:
// AXI4-Lite wrapper for the unified Ascon core
//
// Register map (32-bit registers on 16-byte boundaries, see docs/REGISTER_MAP.md)
//   0x000 CONTROL     W/R  bit0 start, bit1 soft reset, bits3:2 mode
//                          (0 hash, 1 encrypt, 2 decrypt), bit4 has-AD (info)
//   0x010 STATUS      R    see status_word below
//   0x100..0x130 KEY0..3, 0x140..0x170 NONCE0..3   (little-endian words:
//                          REG0 = bytes 0..3 of the value, REG3 = bytes 12..15)
//   0x200..0x230 INPUT0..3  input block (hash uses INPUT0/INPUT1 = bytes 0..7)
//   0x240 INPUT_META  W    bit31 push, bit9 AD block, bit8 last, bits4:0 bytes
//   0x300..0x330 OUTPUT0..3, 0x340 OUTPUT_META (bit14 last, bits4:0 bytes),
//   0x350 OUTPUT_POP  W    bit0 = 1 releases the output mailbox
//   0x400..0x430 TAG0..3,   0x440 TAG_POP (bit0 = 1 releases the tag)
//
// Dependencies: 
//
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
//
//////////////////////////////////////////////////////////////////////////////////


module ascon_aead_hash_axi #(
    parameter integer C_S_AXI_DATA_WIDTH = 32,
    parameter integer C_S_AXI_ADDR_WIDTH = 12,
    parameter integer SPLIT_ROUND        = 0,
    parameter integer MERGE_ABSORB       = 0
) (
    (* X_INTERFACE_PARAMETER = "XIL_INTERFACENAME S_AXI_CLK, ASSOCIATED_BUSIF S_AXI, ASSOCIATED_RESET s_axi_aresetn" *)
    (* X_INTERFACE_INFO = "xilinx.com:signal:clock:1.0 S_AXI_CLK CLK" *)
    input  wire                              s_axi_aclk,
    (* X_INTERFACE_PARAMETER = "XIL_INTERFACENAME S_AXI_RST, POLARITY ACTIVE_LOW" *)
    (* X_INTERFACE_INFO = "xilinx.com:signal:reset:1.0 S_AXI_RST RST" *)
    input  wire                              s_axi_aresetn,
    (* X_INTERFACE_PARAMETER = "XIL_INTERFACENAME S_AXI, PROTOCOL AXI4LITE, DATA_WIDTH 32, ADDR_WIDTH 12, READ_WRITE_MODE READ_WRITE" *)
    (* X_INTERFACE_INFO = "xilinx.com:interface:aximm:1.0 S_AXI AWADDR" *)
    input  wire [C_S_AXI_ADDR_WIDTH-1:0]     s_axi_awaddr,
    (* X_INTERFACE_INFO = "xilinx.com:interface:aximm:1.0 S_AXI AWVALID" *)
    input  wire                              s_axi_awvalid,
    (* X_INTERFACE_INFO = "xilinx.com:interface:aximm:1.0 S_AXI AWREADY" *)
    output wire                              s_axi_awready,
    (* X_INTERFACE_INFO = "xilinx.com:interface:aximm:1.0 S_AXI WDATA" *)
    input  wire [C_S_AXI_DATA_WIDTH-1:0]     s_axi_wdata,
    (* X_INTERFACE_INFO = "xilinx.com:interface:aximm:1.0 S_AXI WSTRB" *)
    input  wire [(C_S_AXI_DATA_WIDTH/8)-1:0] s_axi_wstrb,
    (* X_INTERFACE_INFO = "xilinx.com:interface:aximm:1.0 S_AXI WVALID" *)
    input  wire                              s_axi_wvalid,
    (* X_INTERFACE_INFO = "xilinx.com:interface:aximm:1.0 S_AXI WREADY" *)
    output wire                              s_axi_wready,
    (* X_INTERFACE_INFO = "xilinx.com:interface:aximm:1.0 S_AXI BRESP" *)
    output reg  [1:0]                        s_axi_bresp,
    (* X_INTERFACE_INFO = "xilinx.com:interface:aximm:1.0 S_AXI BVALID" *)
    output reg                               s_axi_bvalid,
    (* X_INTERFACE_INFO = "xilinx.com:interface:aximm:1.0 S_AXI BREADY" *)
    input  wire                              s_axi_bready,
    (* X_INTERFACE_INFO = "xilinx.com:interface:aximm:1.0 S_AXI ARADDR" *)
    input  wire [C_S_AXI_ADDR_WIDTH-1:0]     s_axi_araddr,
    (* X_INTERFACE_INFO = "xilinx.com:interface:aximm:1.0 S_AXI ARVALID" *)
    input  wire                              s_axi_arvalid,
    (* X_INTERFACE_INFO = "xilinx.com:interface:aximm:1.0 S_AXI ARREADY" *)
    output wire                              s_axi_arready,
    (* X_INTERFACE_INFO = "xilinx.com:interface:aximm:1.0 S_AXI RDATA" *)
    output reg  [C_S_AXI_DATA_WIDTH-1:0]     s_axi_rdata,
    (* X_INTERFACE_INFO = "xilinx.com:interface:aximm:1.0 S_AXI RRESP" *)
    output reg  [1:0]                        s_axi_rresp,
    (* X_INTERFACE_INFO = "xilinx.com:interface:aximm:1.0 S_AXI RVALID" *)
    output reg                               s_axi_rvalid,
    (* X_INTERFACE_INFO = "xilinx.com:interface:aximm:1.0 S_AXI RREADY" *)
    input  wire                              s_axi_rready
);
    localparam [1:0] MODE_HASH = 2'd0;
    localparam [1:0] MODE_ENC  = 2'd1;
    localparam [1:0] MODE_DEC  = 2'd2;

    localparam [11:0] A_CONTROL     = 12'h000;
    localparam [11:0] A_STATUS      = 12'h010;
    localparam [11:0] A_KEY0        = 12'h100;
    localparam [11:0] A_KEY1        = 12'h110;
    localparam [11:0] A_KEY2        = 12'h120;
    localparam [11:0] A_KEY3        = 12'h130;
    localparam [11:0] A_NONCE0      = 12'h140;
    localparam [11:0] A_NONCE1      = 12'h150;
    localparam [11:0] A_NONCE2      = 12'h160;
    localparam [11:0] A_NONCE3      = 12'h170;
    localparam [11:0] A_INPUT0      = 12'h200;
    localparam [11:0] A_INPUT1      = 12'h210;
    localparam [11:0] A_INPUT2      = 12'h220;
    localparam [11:0] A_INPUT3      = 12'h230;
    localparam [11:0] A_INPUT_META  = 12'h240;
    localparam [11:0] A_OUTPUT0     = 12'h300;
    localparam [11:0] A_OUTPUT1     = 12'h310;
    localparam [11:0] A_OUTPUT2     = 12'h320;
    localparam [11:0] A_OUTPUT3     = 12'h330;
    localparam [11:0] A_OUTPUT_META = 12'h340;
    localparam [11:0] A_OUTPUT_POP  = 12'h350;
    localparam [11:0] A_TAG0        = 12'h400;
    localparam [11:0] A_TAG1        = 12'h410;
    localparam [11:0] A_TAG2        = 12'h420;
    localparam [11:0] A_TAG3        = 12'h430;
    localparam [11:0] A_TAG_POP     = 12'h440;

    // ------------------------------------------------------------------
    // AXI4-Lite write / read channel handling (single outstanding beat)
    // ------------------------------------------------------------------
    reg                           aw_hold, w_hold;
    reg [C_S_AXI_ADDR_WIDTH-1:0]  awaddr_hold;
    reg [31:0]                    wdata_hold;
    reg [3:0]                     wstrb_hold;

    assign s_axi_awready = ~aw_hold & ~s_axi_bvalid;
    assign s_axi_wready  = ~w_hold  & ~s_axi_bvalid;
    assign s_axi_arready = ~s_axi_rvalid;

    wire do_write = aw_hold & w_hold & ~s_axi_bvalid;
    wire do_read  = s_axi_arready & s_axi_arvalid;

    function [31:0] merge_wstrb;
        input [31:0] old_value;
        input [31:0] new_value;
        input [3:0]  strobes;
        integer i;
        begin
            merge_wstrb = old_value;
            for (i = 0; i < 4; i = i + 1)
                if (strobes[i])
                    merge_wstrb[i*8 +: 8] = new_value[i*8 +: 8];
        end
    endfunction

    // ------------------------------------------------------------------
    // Software-visible registers and mailboxes
    // ------------------------------------------------------------------
    reg [1:0]   op_mode;
    reg         has_ad_reg;
    reg         error_flag;
    reg         core_start;
    reg         soft_reset;

    reg [31:0]  key_w0, key_w1, key_w2, key_w3;
    reg [31:0]  nonce_w0, nonce_w1, nonce_w2, nonce_w3;
    reg [31:0]  input_w0, input_w1, input_w2, input_w3;

    reg         input_pending;
    reg         input_is_ad;
    reg         input_last;
    reg [4:0]   input_len;

    reg         output_pending;
    reg         output_last;
    reg [4:0]   output_len;
    reg [127:0] output_data;

    reg         tag_pending;
    reg         tag_seen;
    reg [127:0] tag_data;

    wire [127:0] key_value   = {key_w3,   key_w2,   key_w1,   key_w0};
    wire [127:0] nonce_value = {nonce_w3, nonce_w2, nonce_w1, nonce_w0};
    wire [127:0] input_value = {input_w3, input_w2, input_w1, input_w0};

    // ------------------------------------------------------------------
    // Unified core
    // ------------------------------------------------------------------
    wire         core_rst = ~s_axi_aresetn | soft_reset;
    wire         core_busy;
    wire         core_in_ready, core_in_ready_ad, core_in_ready_msg;
    wire         core_out_valid;
    wire [127:0] core_out_data;
    wire [4:0]   core_out_len;
    wire         core_out_last;
    wire         core_tag_valid;
    wire [127:0] core_tag;
    wire         core_out_ready = ~output_pending;

    ascon_aead_hash #(
        .SPLIT_ROUND  (SPLIT_ROUND),
        .MERGE_ABSORB (MERGE_ABSORB)
    ) u_core (
        .clk          (s_axi_aclk),
        .rst          (core_rst),
        .start        (core_start),
        .mode         (op_mode),
        .key          (key_value),
        .nonce        (nonce_value),
        .busy         (core_busy),
        .in_valid     (input_pending),
        .in_data      (input_value),
        .in_len       (input_len),
        .in_last      (input_last),
        .in_ad        (input_is_ad),
        .in_ready     (core_in_ready),
        .in_ready_ad  (core_in_ready_ad),
        .in_ready_msg (core_in_ready_msg),
        .out_valid    (core_out_valid),
        .out_data     (core_out_data),
        .out_len      (core_out_len),
        .out_last     (core_out_last),
        .out_ready    (core_out_ready),
        .tag_valid    (core_tag_valid),
        .tag          (core_tag)
    );

    wire input_accepted = input_pending & core_in_ready;
    wire output_xfer    = core_out_valid & core_out_ready;
    wire selected_ready = input_is_ad ? core_in_ready_ad : core_in_ready_msg;

    wire [31:0] status_word;
    assign status_word[31:12] = 20'd0;
    assign status_word[11]    = error_flag;
    assign status_word[10]    = tag_pending;
    assign status_word[9]     = output_last;
    assign status_word[8]     = output_pending;
    assign status_word[7]     = input_pending;
    assign status_word[6]     = selected_ready;
    assign status_word[5]     = core_in_ready_msg;
    assign status_word[4]     = core_in_ready_ad;
    assign status_word[3:2]   = op_mode;
    assign status_word[1]     = core_busy;
    assign status_word[0]     = 1'b1;

    wire [4:0] max_len = (op_mode == MODE_HASH) ? 5'd8 : 5'd16;

    always @(posedge s_axi_aclk) begin
        if (!s_axi_aresetn) begin
            aw_hold        <= 1'b0;
            w_hold         <= 1'b0;
            awaddr_hold    <= {C_S_AXI_ADDR_WIDTH{1'b0}};
            wdata_hold     <= 32'd0;
            wstrb_hold     <= 4'd0;
            s_axi_bvalid   <= 1'b0;
            s_axi_bresp    <= 2'b00;
            s_axi_rvalid   <= 1'b0;
            s_axi_rresp    <= 2'b00;
            s_axi_rdata    <= 32'd0;
            op_mode        <= MODE_HASH;
            has_ad_reg     <= 1'b0;
            error_flag     <= 1'b0;
            core_start     <= 1'b0;
            soft_reset     <= 1'b0;
            key_w0 <= 32'd0; key_w1 <= 32'd0; key_w2 <= 32'd0; key_w3 <= 32'd0;
            nonce_w0 <= 32'd0; nonce_w1 <= 32'd0; nonce_w2 <= 32'd0; nonce_w3 <= 32'd0;
            input_w0 <= 32'd0; input_w1 <= 32'd0; input_w2 <= 32'd0; input_w3 <= 32'd0;
            input_pending  <= 1'b0;
            input_is_ad    <= 1'b0;
            input_last     <= 1'b0;
            input_len      <= 5'd0;
            output_pending <= 1'b0;
            output_last    <= 1'b0;
            output_len     <= 5'd0;
            output_data    <= 128'd0;
            tag_pending    <= 1'b0;
            tag_seen       <= 1'b0;
            tag_data       <= 128'd0;
        end else begin
            core_start <= 1'b0;
            soft_reset <= 1'b0;

            // ---- write address / data capture ----------------------------
            if (s_axi_awready && s_axi_awvalid) begin
                awaddr_hold <= s_axi_awaddr;
                aw_hold     <= 1'b1;
            end
            if (s_axi_wready && s_axi_wvalid) begin
                wdata_hold <= s_axi_wdata;
                wstrb_hold <= s_axi_wstrb;
                w_hold     <= 1'b1;
            end
            if (s_axi_bvalid && s_axi_bready)
                s_axi_bvalid <= 1'b0;

            // ---- register write ------------------------------------------
            if (do_write) begin
                aw_hold      <= 1'b0;
                w_hold       <= 1'b0;
                s_axi_bvalid <= 1'b1;
                s_axi_bresp  <= 2'b00;
                case (awaddr_hold[11:0])
                    A_CONTROL: begin
                        if (wstrb_hold[0]) begin
                            if (wdata_hold[1]) begin           // soft reset
                                soft_reset     <= 1'b1;
                                input_pending  <= 1'b0;
                                output_pending <= 1'b0;
                                tag_pending    <= 1'b0;
                                tag_seen       <= 1'b0;
                                error_flag     <= 1'b0;
                            end
                            if (wdata_hold[0]) begin           // start
                                if (wdata_hold[3:2] == 2'd3) begin
                                    error_flag <= 1'b1;
                                end else begin
                                    op_mode        <= wdata_hold[3:2];
                                    has_ad_reg     <= wdata_hold[4];
                                    core_start     <= 1'b1;
                                    input_pending  <= 1'b0;
                                    output_pending <= 1'b0;
                                    tag_pending    <= 1'b0;
                                    tag_seen       <= 1'b0;
                                    error_flag     <= 1'b0;
                                end
                            end
                        end
                    end
                    A_KEY0:   key_w0   <= merge_wstrb(key_w0,   wdata_hold, wstrb_hold);
                    A_KEY1:   key_w1   <= merge_wstrb(key_w1,   wdata_hold, wstrb_hold);
                    A_KEY2:   key_w2   <= merge_wstrb(key_w2,   wdata_hold, wstrb_hold);
                    A_KEY3:   key_w3   <= merge_wstrb(key_w3,   wdata_hold, wstrb_hold);
                    A_NONCE0: nonce_w0 <= merge_wstrb(nonce_w0, wdata_hold, wstrb_hold);
                    A_NONCE1: nonce_w1 <= merge_wstrb(nonce_w1, wdata_hold, wstrb_hold);
                    A_NONCE2: nonce_w2 <= merge_wstrb(nonce_w2, wdata_hold, wstrb_hold);
                    A_NONCE3: nonce_w3 <= merge_wstrb(nonce_w3, wdata_hold, wstrb_hold);
                    A_INPUT0: input_w0 <= merge_wstrb(input_w0, wdata_hold, wstrb_hold);
                    A_INPUT1: input_w1 <= merge_wstrb(input_w1, wdata_hold, wstrb_hold);
                    A_INPUT2: input_w2 <= merge_wstrb(input_w2, wdata_hold, wstrb_hold);
                    A_INPUT3: input_w3 <= merge_wstrb(input_w3, wdata_hold, wstrb_hold);
                    A_INPUT_META: begin
                        if (wstrb_hold[3] && wdata_hold[31]) begin
                            if (input_pending || (wdata_hold[4:0] > max_len)) begin
                                error_flag <= 1'b1;
                            end else begin
                                input_pending <= 1'b1;
                                input_is_ad   <= wdata_hold[9] && (op_mode != MODE_HASH);
                                input_last    <= wdata_hold[8];
                                input_len     <= wdata_hold[4:0];
                            end
                        end
                    end
                    A_OUTPUT_POP: if (wstrb_hold[0] && wdata_hold[0]) output_pending <= 1'b0;
                    A_TAG_POP:    if (wstrb_hold[0] && wdata_hold[0]) tag_pending    <= 1'b0;
                    default: begin
                        s_axi_bresp <= 2'b10;                  // SLVERR
                        error_flag  <= 1'b1;
                    end
                endcase
            end

            // ---- core handshakes ------------------------------------------
            if (input_accepted)
                input_pending <= 1'b0;

            if (output_xfer) begin
                output_data    <= core_out_data;
                output_len     <= core_out_len;
                output_last    <= core_out_last;
                output_pending <= 1'b1;
            end

            if (core_tag_valid && !tag_seen) begin
                tag_data    <= core_tag;
                tag_pending <= 1'b1;
                tag_seen    <= 1'b1;
            end

            // ---- register read -------------------------------------------
            if (s_axi_rvalid && s_axi_rready)
                s_axi_rvalid <= 1'b0;
            if (do_read) begin
                s_axi_rvalid <= 1'b1;
                s_axi_rresp  <= 2'b00;
                case (s_axi_araddr[11:0])
                    A_CONTROL:     s_axi_rdata <= {27'd0, has_ad_reg, op_mode, 2'd0};
                    A_STATUS:      s_axi_rdata <= status_word;
                    A_KEY0:        s_axi_rdata <= key_w0;
                    A_KEY1:        s_axi_rdata <= key_w1;
                    A_KEY2:        s_axi_rdata <= key_w2;
                    A_KEY3:        s_axi_rdata <= key_w3;
                    A_NONCE0:      s_axi_rdata <= nonce_w0;
                    A_NONCE1:      s_axi_rdata <= nonce_w1;
                    A_NONCE2:      s_axi_rdata <= nonce_w2;
                    A_NONCE3:      s_axi_rdata <= nonce_w3;
                    A_INPUT0:      s_axi_rdata <= input_w0;
                    A_INPUT1:      s_axi_rdata <= input_w1;
                    A_INPUT2:      s_axi_rdata <= input_w2;
                    A_INPUT3:      s_axi_rdata <= input_w3;
                    A_OUTPUT0:     s_axi_rdata <= output_data[31:0];
                    A_OUTPUT1:     s_axi_rdata <= output_data[63:32];
                    A_OUTPUT2:     s_axi_rdata <= output_data[95:64];
                    A_OUTPUT3:     s_axi_rdata <= output_data[127:96];
                    A_OUTPUT_META: s_axi_rdata <= {17'd0, output_last, 9'd0, output_len};
                    A_TAG0:        s_axi_rdata <= tag_data[31:0];
                    A_TAG1:        s_axi_rdata <= tag_data[63:32];
                    A_TAG2:        s_axi_rdata <= tag_data[95:64];
                    A_TAG3:        s_axi_rdata <= tag_data[127:96];
                    default: begin
                        s_axi_rdata <= 32'd0;
                        s_axi_rresp <= 2'b10;                  // SLVERR
                    end
                endcase
            end
        end
    end
endmodule
