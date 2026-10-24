`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 10/24/2026 11:04:29 AM
// Design Name: 
// Module Name: ascon_lut6
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module ascon_lut6 #(
    parameter [63:0] INIT = 64'h0000_0000_0000_0000
) (
    input  wire I0, I1, I2, I3, I4, I5,
    output wire O
);
`ifdef SYNTHESIS
    (* DONT_TOUCH = "true" *) LUT6 #(.INIT(INIT)) u_lut (.O(O), .I0(I0), .I1(I1), .I2(I2), .I3(I3), .I4(I4), .I5(I5));
`else
    assign O = INIT[{I5, I4, I3, I2, I1, I0}];
`endif
endmodule
