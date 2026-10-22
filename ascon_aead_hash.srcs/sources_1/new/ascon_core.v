`timescale 1ns / 1ps
// ============================================================================
// ascon_core.v -- Ascon permutation building blocks (NIST SP 800-232)
//
// Convention (identical to SP 800-232): the 320-bit state is five 64-bit
// words S0..S4.  Each word is the little-endian integer of its 8 bytes, i.e.
// byte 0 of the stream sits in bits [7:0] of S0.  The 320-bit bus used here
// is {S0, S1, S2, S3, S4} with S0 in bits [319:256].
//
// The round is split into two modules so the datapath can optionally place a
// register between the substitution layer and the linear layer
// (SPLIT_ROUND = 1 in ascon_aead_hash_datapath).
// ============================================================================

// ----------------------------------------------------------------------------
// Constant addition + substitution layer (the non-linear half of a round)
// ----------------------------------------------------------------------------
module ascon_round_sbox (
    input  wire [3:0]   round_idx,   // 0..11 ; p12 runs 0..11, p8 runs 4..11
    input  wire [319:0] x_in,
    output wire [319:0] x_out
);
    wire [63:0] x0, x1, x2, x3, x4;
    assign {x0, x1, x2, x3, x4} = x_in;

    // c_r = 0xf0 - r*0x10 + r  ==  {~r, r} for r in 0..11
    wire [7:0]  round_const = {~round_idx, round_idx};
    wire [63:0] x2c = x2 ^ {56'd0, round_const};

    // substitution layer (bit-sliced 5-bit S-box)
    wire [63:0] s0 = x0  ^ x4;
    wire [63:0] s1 = x1;
    wire [63:0] s2 = x2c ^ x1;
    wire [63:0] s3 = x3;
    wire [63:0] s4 = x4  ^ x3;

    wire [63:0] t0 = (~s0) & s1;
    wire [63:0] t1 = (~s1) & s2;
    wire [63:0] t2 = (~s2) & s3;
    wire [63:0] t3 = (~s3) & s4;
    wire [63:0] t4 = (~s4) & s0;

    wire [63:0] u0 = s0 ^ t1;
    wire [63:0] u1 = s1 ^ t2;
    wire [63:0] u2 = s2 ^ t3;
    wire [63:0] u3 = s3 ^ t4;
    wire [63:0] u4 = s4 ^ t0;

    wire [63:0] v0 = u0 ^ u4;
    wire [63:0] v1 = u1 ^ u0;
    wire [63:0] v2 = ~u2;
    wire [63:0] v3 = u3 ^ u2;
    wire [63:0] v4 = u4;

    assign x_out = {v0, v1, v2, v3, v4};
endmodule

// ----------------------------------------------------------------------------
// Linear diffusion layer.  Rotations are pure wiring (zero logic).
// ----------------------------------------------------------------------------
module ascon_round_linear (
    input  wire [319:0] x_in,
    output wire [319:0] x_out
);
    wire [63:0] v0, v1, v2, v3, v4;
    assign {v0, v1, v2, v3, v4} = x_in;

    wire [63:0] y0 = v0 ^ {v0[18:0], v0[63:19]} ^ {v0[27:0], v0[63:28]};
    wire [63:0] y1 = v1 ^ {v1[60:0], v1[63:61]} ^ {v1[38:0], v1[63:39]};
    wire [63:0] y2 = v2 ^ {v2[0:0],  v2[63:1]}  ^ {v2[5:0],  v2[63:6]};
    wire [63:0] y3 = v3 ^ {v3[9:0],  v3[63:10]} ^ {v3[16:0], v3[63:17]};
    wire [63:0] y4 = v4 ^ {v4[6:0],  v4[63:7]}  ^ {v4[40:0], v4[63:41]};

    assign x_out = {y0, y1, y2, y3, y4};
endmodule

// ----------------------------------------------------------------------------
// One full combinational round p (constant add -> S-box -> linear layer)
// ----------------------------------------------------------------------------
module ascon_round (
    input  wire [3:0]   round_idx,
    input  wire [319:0] x_in,
    output wire [319:0] x_out
);
    wire [319:0] sbox_out;
    ascon_round_sbox   u_sbox (.round_idx(round_idx), .x_in(x_in),     .x_out(sbox_out));
    ascon_round_linear u_lin  (.x_in(sbox_out),       .x_out(x_out));
endmodule
