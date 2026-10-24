`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: Muhammad Ogin Hasanuddin
// 
// Create Date: 10/24/2026 11:05:06 AM
// Design Name: 
// Module Name: ascon_lut5
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 5-input look-up tables with explicit
// truth tables.  In synthesis (Vivado defines SYNTHESIS) they are Xilinx
// LUT5 / LUT6 primitives marked DONT_TOUCH, so neither the mapper nor the
// physical optimizer splits, merges or restructures them; in
// simulation the same truth table is evaluated behaviourally.
//   O = INIT[{I4, I3, I2, I1, I0}]   /   O = INIT[{I5, I4, I3, I2, I1, I0}]
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module ascon_lut5 #(
    parameter [31:0] INIT = 32'h0000_0000
) (
    input  wire I0, I1, I2, I3, I4,
    output wire O
);
`ifdef SYNTHESIS
    (* DONT_TOUCH = "true" *) LUT5 #(.INIT(INIT)) u_lut (.O(O), .I0(I0), .I1(I1), .I2(I2), .I3(I3), .I4(I4));
`else
    assign O = INIT[{I4, I3, I2, I1, I0}];
`endif
endmodule
