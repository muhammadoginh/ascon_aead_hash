`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: Muhammad Ogin Hasanuddin
// 
// Create Date: 10/24/2026 11:05:06 AM
// Design Name: 
// Module Name: ascon_lut6_2
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// dual-output LUT: O6 = INIT[{I5..I0}], O5 = INIT[{1'b0, I4..I0}].  With I5 tied
// high it holds two independent 5-input functions of the same inputs
// (INIT[31:0] on O5, INIT[63:32] on O6) in one slice LUT.
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module ascon_lut6_2 #(
    parameter [63:0] INIT = 64'h0000_0000_0000_0000
) (
    input  wire I0, I1, I2, I3, I4, I5,
    output wire O5, O6
);
`ifdef SYNTHESIS
    (* DONT_TOUCH = "true" *) LUT6_2 #(.INIT(INIT)) u_lut (.O5(O5), .O6(O6), .I0(I0), .I1(I1), .I2(I2), .I3(I3), .I4(I4), .I5(I5));
`else
    assign O6 = INIT[{I5, I4, I3, I2, I1, I0}];
    assign O5 = INIT[{1'b0, I4, I3, I2, I1, I0}];
`endif
endmodule
