# Ascon Hardware Block Design Guide

This document provides the hardware block designs for **Ascon-128a** (AEAD Encryption/Decryption) and **Ascon-Hash256**, spanning from high-level system blocks down to individual gate-level operator connections.

---

## 1. High-Level System Block Diagram
The Ascon IP core contains two main modules sharing a single clock and reset domain: `ascon_aead` for authenticated encryption/decryption and `ascon_hash` for hashing. Both modules reuse the same combinational permutation core (`ascon_round`).

```mermaid
graph TD
    subgraph System Interconnect
        CLK[clk]
        RST[rst]
        KEY[key_in 128]
        NONCE[nonce_in 128]
        AD_DATA[ad_data 128]
        PT_DATA[pt_data 128]
        HASH_IN[hash_data_in 64]
    end

    subgraph Ascon Hardware Core
        subgraph ascon_aead [AEAD Engine]
            AEAD_FSM[FSM Controller]
            AEAD_DP[Datapath & State Registers]
            AEAD_PAD[Padding & Masking]
        end

        subgraph ascon_hash [Hash Engine]
            HASH_FSM[FSM Controller]
            HASH_DP[Datapath & State Registers]
            HASH_PAD[Padding & Masking]
        end

        subgraph PermutationCore [ascon_round core_inst]
            R_CONST[Constant Addition]
            S_BOX[Substitution Layer]
            L_DIFF[Linear Diffusion]
        end
    end

    KEY --> AEAD_DP
    NONCE --> AEAD_DP
    AD_DATA --> AEAD_PAD
    PT_DATA --> AEAD_PAD
    HASH_IN --> HASH_PAD

    AEAD_DP <--> PermutationCore
    HASH_DP <--> PermutationCore

    AEAD_DP --> AEAD_OUT[out_data 128]
    AEAD_DP --> TAG_OUT[tag 128]
    HASH_DP --> HASH_OUT[hash_out 64]
```

---

## 2. Module-Level Block Designs

### 2.1. Ascon AEAD (`ascon_aead`)
The AEAD module consists of a control path (Finite State Machine) and a datapath containing the 320-bit state registers, key/nonce buffers, and the padding/masking circuits.

```mermaid
graph TD
    subgraph Control Path
        FSM[AEAD FSM Controller]
        R_CTR[Round Counter 4-bit]
        FSM -->|round_idx| R_CTR
        FSM -->|Select Signals| MUX_STATE
        FSM -->|Enable / Load| STATE_REG
    end

    subgraph Datapath Input Interfaces
        I_KEY[Key Buffer 128-bit]
        I_NONCE[Nonce Buffer 128-bit]
        I_AD[AD Data input 128-bit]
        I_PT[PT Data input 128-bit]
    end

    subgraph Padding and Masking Logic
        PAD_AD[apply_pad AD]
        PAD_PT[apply_pad PT / CT]
        MASK_CT[apply_mask CT / PT]
        
        I_AD --> PAD_AD
        I_PT --> PAD_PT
        PAD_PT --> MASK_CT
    end

    subgraph State Registers & Permutation
        STATE_REG[320-bit State Register: s0-s4]
        ROUND_CORE[ascon_round Permutation Core]
        
        STATE_REG -->|x_in| ROUND_CORE
    end

    subgraph State Update Muxing
        MUX_STATE{State Mux}
        ROUND_CORE -->|x_out| MUX_STATE
        I_KEY --> MUX_STATE
        I_NONCE --> MUX_STATE
        PAD_AD --> MUX_STATE
        PAD_PT --> MUX_STATE
        
        MUX_STATE -->|next_s| STATE_REG
    end

    subgraph Output Interfaces
        MASK_CT --> O_DATA[out_data 128-bit]
        STATE_REG -->|s3, s4| O_TAG[tag 128-bit]
    end
```

---

### 2.2. Ascon Hash (`ascon_hash`)
The Hash module uses 64-bit rate blocks. It preloads a constant precomputed initialization state on reset, avoiding 12 clock cycles of initial permutation.

```mermaid
graph TD
    subgraph Control Path
        FSM[Hash FSM Controller]
        R_CTR[Round Counter 4-bit]
        S_CTR[Squeeze Counter 3-bit]
        FSM -->|inc_round| R_CTR
        FSM -->|inc_squeeze| S_CTR
        FSM -->|Select/Enable| STATE_REG
    end

    subgraph Input & Padding
        I_DATA[data_in 64-bit]
        PAD[Padding Generator]
        I_DATA --> PAD
    end

    subgraph State & Permutation
        INIT_CONST[Precomputed Hash Init Constants]
        STATE_REG[320-bit State Register: s0-s4]
        ROUND_CORE[ascon_round Permutation Core]
        
        INIT_CONST -->|on reset| STATE_REG
        STATE_REG -->|x_in| ROUND_CORE
    end

    subgraph State Update & Squeezing
        MUX_STATE{State Mux}
        XOR_ABSORB(XOR)
        
        STATE_REG -->|s0| XOR_ABSORB
        PAD -->|padded_data| XOR_ABSORB
        
        XOR_ABSORB --> MUX_STATE
        ROUND_CORE -->|x_out| MUX_STATE
        
        MUX_STATE -->|next_s| STATE_REG
    end

    subgraph Output
        STATE_REG -->|s0| O_HASH[hash_out 64-bit]
    end
```

---

## 3. Permutation Round Datapath (`ascon_round`)
The core permutation module is fully combinational, processing the 320-bit state in a single clock cycle.

```mermaid
graph LR
    subgraph Inputs
        X_IN[x_in 320-bit]
        R_IDX[round_idx 4-bit]
    end

    subgraph Constant Addition p_C
        ROM[Round Constant ROM]
        XOR_C(XOR)
        R_IDX --> ROM
        X_IN -->|x0, x1| S_BOX_IN
        X_IN -->|x2| XOR_C
        ROM -->|round_const| XOR_C
        X_IN -->|x3, x4| S_BOX_IN
    end

    subgraph S-Box Substitution p_S
        S_BOX_IN[320-bit State]
        XOR_C --> S_BOX_IN
        S_BOX_SLICES[64 x Parallel 5-bit S-Box Slices]
        S_BOX_IN --> S_BOX_SLICES
    end

    subgraph Linear Diffusion p_L
        S_BOX_OUT[320-bit Intermediate State]
        S_BOX_SLICES --> S_BOX_OUT
        DIFF_0[Sigma_0 x0]
        DIFF_1[Sigma_1 x1]
        DIFF_2[Sigma_2 x2]
        DIFF_3[Sigma_3 x3]
        DIFF_4[Sigma_4 x4]
        
        S_BOX_OUT -->|v0| DIFF_0
        S_BOX_OUT -->|v1| DIFF_1
        S_BOX_OUT -->|v2| DIFF_2
        S_BOX_OUT -->|v3| DIFF_3
        S_BOX_OUT -->|v4| DIFF_4
    end

    subgraph Outputs
        DIFF_0 -->|y0| X_OUT[x_out 320-bit]
        DIFF_1 -->|y1| X_OUT
        DIFF_2 -->|y2| X_OUT
        DIFF_3 -->|y3| X_OUT
        DIFF_4 -->|y4| X_OUT
    end
```

---

## 4. Operator-Level Logic Designs

### 4.1. Gate-Level S-Box Slice ($p_S$)
The S-box processes a single bit slice $i$ ($0 \le i < 64$) across the 5 state words. 64 identical copies of this circuit run in parallel.

```mermaid
graph TD
    subgraph S-Box Inputs
        x0[x0_i]
        x1[x1_i]
        x2[x2_i]
        x3[x3_i]
        x4[x4_i]
    end

    subgraph Phase 1: Pre-XOR Mixing
        XOR_S0(XOR)
        XOR_S2(XOR)
        XOR_S4(XOR)
        
        x0 --> XOR_S0
        x4 --> XOR_S0
        
        x2 --> XOR_S2
        x1 --> XOR_S2
        
        x4 --> XOR_S4
        x3 --> XOR_S4
        
        XOR_S0 -->|s0| NOT_S0
        x1 -->|s1| NOT_S1
        XOR_S2 -->|s2| NOT_S2
        x3 -->|s3| NOT_S3
        XOR_S4 -->|s4| NOT_S4
    end

    subgraph Phase 2: Non-Linear Chi Mapping
        NOT_S0[NOT]
        NOT_S1[NOT]
        NOT_S2[NOT]
        NOT_S3[NOT]
        NOT_S4[NOT]
        
        AND_T0(AND)
        AND_T1(AND)
        AND_T2(AND)
        AND_T3(AND)
        AND_T4(AND)
        
        NOT_S0 --> AND_T0
        x1 --> AND_T0
        
        NOT_S1 --> AND_T1
        XOR_S2 --> AND_T1
        
        NOT_S2 --> AND_T2
        x3 --> AND_T2
        
        NOT_S3 --> AND_T3
        XOR_S4 --> AND_T3
        
        NOT_S4 --> AND_T4
        XOR_S0 --> AND_T4
    end

    subgraph Phase 3: Post-XOR Mixing
        XOR_U0(XOR)
        XOR_U1(XOR)
        XOR_U2(XOR)
        XOR_U3(XOR)
        XOR_U4(XOR)
        
        XOR_S0 --> XOR_U0
        AND_T1 --> XOR_U0
        
        x1 --> XOR_U1
        AND_T2 --> XOR_U1
        
        XOR_S2 --> XOR_U2
        AND_T3 --> XOR_U2
        
        x3 --> XOR_U3
        AND_T4 --> XOR_U3
        
        XOR_S4 --> XOR_U4
        AND_T0 --> XOR_U4
    end

    subgraph Phase 4: Output Transform & Inversion
        XOR_V0(XOR)
        XOR_V1(XOR)
        NOT_V2[NOT]
        XOR_V3(XOR)
        
        XOR_U0 --> XOR_V0
        XOR_U4 --> XOR_V0
        
        XOR_U1 --> XOR_V1
        XOR_U0 --> XOR_V1
        
        XOR_U2 --> NOT_V2
        
        XOR_U3 --> XOR_V3
        XOR_U2 --> XOR_V3
    end

    subgraph S-Box Outputs
        XOR_V0 -->|v0_i| v0
        XOR_V1 -->|v1_i| v1
        NOT_V2 -->|v2_i| v2
        XOR_V3 -->|v3_i| v3
        XOR_U4 -->|v4_i| v4
    end
```

---

### 4.2. Linear Diffusion Operators ($p_L$)
The linear diffusion layer consists of 5 word-level channels. It uses wire swizzling for rotations and an XOR tree to mix them.

#### Word 0 Diffusion Block ($x_0$):
$$\Sigma_0(x_0) = x_0 \oplus (x_0 \ggg 19) \oplus (x_0 \ggg 28)$$

```mermaid
graph TD
    V0[Input Word v0 64-bit]
    
    subgraph Rotation Wire Routing
        ROT_19[Wire Concat: v0 18:0, 63:19]
        ROT_28[Wire Concat: v0 27:0, 63:28]
    end
    
    subgraph XOR Mixing Tree
        XOR_1(64-bit XOR Gate)
        XOR_2(64-bit XOR Gate)
    end
    
    V0 --> XOR_1
    ROT_19 --> XOR_1
    
    XOR_1 --> XOR_2
    ROT_28 --> XOR_2
    
    XOR_2 --> Y0[Output Word y0 64-bit]
```

*(Note: Words $x_1$ through $x_4$ use identical XOR mixing tree architectures, but with different hardwired rotation tap-offs).*

---

### 4.3. Padding Generator Operator
The padding generator formats incoming messages to fit block boundaries. It takes raw data and a length parameter to output a padded block and valid bitmask.

```mermaid
graph TD
    LEN[Byte Length: 4-bit / 5-bit]
    DATA_IN[Raw Data: 64-bit / 128-bit]

    subgraph Shift Amount Calculator
        SH_3[Static Left-Shift by 3: wiring]
        SUB_OFF[Subtractor: Max_Bits - Shift_Bits]
        
        LEN --> SH_3
        SH_3 -->|shift_bits| SUB_OFF
    end

    subgraph Mask Generator
        ALL_ONES[Constant All-Ones Block]
        BARREL_SH_MASK[Barrel Shifter]
        
        ALL_ONES --> BARREL_SH_MASK
        SUB_OFF -->|shift_offset| BARREL_SH_MASK
    end

    subgraph Pad Byte Generator
        PAD_START_VAL[Constant Single-Bit Pad 0x80]
        SUB_PAD_OFF[Subtractor: Max_Bits - shift_bits_plus_one]
        BARREL_SH_PAD[Barrel Shifter]
        ADD_1[Adder: len + 1]
        
        LEN --> ADD_1
        ADD_1 -->|len_plus_1| SUB_PAD_OFF
        PAD_START_VAL --> BARREL_SH_PAD
        SUB_PAD_OFF --> BARREL_SH_PAD
    end

    subgraph Masking and Merging
        AND_MASK(Bitwise AND)
        OR_PAD(Bitwise OR)
        
        DATA_IN --> AND_MASK
        BARREL_SH_MASK -->|pad_mask| AND_MASK
        
        AND_MASK --> OR_PAD
        BARREL_SH_PAD -->|pad_byte| OR_PAD
    end

    OR_PAD --> PADDED_DATA[padded_data]
```
*   **Adder:** Computes `len + 1` to locate the padding boundary.
*   **Subtractors:** Compute `Max_Bits - (len * 8)` and `Max_Bits - ((len + 1) * 8)` to define the shift offsets.
*   **Barrel Shifters:** Perform variable shifts based on the computed shift offsets to align the mask and padding byte.
*   **AND/OR Operators:** Apply the mask and insert the pad bit into the data stream.
