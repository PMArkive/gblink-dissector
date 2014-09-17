/*
 * Copyright (c) 2014 Nicholas Corgan (n.corgan@gmail.com)
 *
 * Distributed under the MIT License (MIT) (See accompanying file LICENSE.txt
 * or copy at http://opensource.org/licenses/MIT)
 */

#include <ctype.h>

#include <wireshark/config.h>
#include <epan/packet.h>

const unsigned int BGBLINK_PORT = 8765;

static int proto_bgblink = -1;

static int hf_bgblink_b1 = -1; //Command
static int hf_bgblink_b2 = -1;
static int hf_bgblink_b3 = -1;
static int hf_bgblink_b4 = -1;
static int hf_bgblink_i1 = -1; //Timestamp

static int ett_bgblink = -1;

//Forward declaration of dissector functions
void proto_register_bgblink(void);
void proto_reg_handoff_bgblink(void);
static void dissect_bgblink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_bgblink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint offset = 0;
    gint len = tvb_reported_length(tvb);

    col_append_str(pinfo->cinfo, COL_PROTOCOL, "BGB");
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "BGB", tvb_format_text_wsp(tvb, 0, len));

    if(tree)
    {
        proto_item* ti = NULL;
        proto_tree* bgblink_tree = NULL;

        ti = proto_tree_add_item(tree, proto_bgblink, tvb, 0, -1, ENC_NA);
        bgblink_tree = proto_item_add_subtree(ti, ett_bgblink);

        proto_tree_add_item(bgblink_tree, hf_bgblink_b1, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(bgblink_tree, hf_bgblink_b2, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(bgblink_tree, hf_bgblink_b3, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(bgblink_tree, hf_bgblink_b4, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(bgblink_tree, hf_bgblink_i1, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
}

void proto_register_bgblink(void)
{
    static hf_register_info hf[] = {
        {
            &hf_bgblink_b1,
            {
                "B1/Command", "bgblink.b1",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                "Byte 1 / Link Command", HFILL
            }
        },
        {
            &hf_bgblink_b2,
            {
                "B2", "bgblink.b2",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                "Byte 2", HFILL
            }
        },
        {
            &hf_bgblink_b3,
            {
                "B3", "bgblink.b3",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                "Byte 3", HFILL
            }
        },
        {
            &hf_bgblink_b4,
            {
                "B4", "bgblink.b4",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                "Byte 4", HFILL
            }
        },
        {
            &hf_bgblink_i1,
            {
                "I1/Timestamp", "bgblink.i1",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                "Timestamp", HFILL
            }
        }
    };

    proto_bgblink = proto_register_protocol("BGB Link Cable Protocol", "BGB Link", "bgblink");
    proto_register_field_array(proto_bgblink, hf, array_length(hf));
    register_dissector("bgblink", dissect_bgblink, proto_bgblink);
}

//Handler registration
void proto_reg_handoff_bgblink(void)
{
    static dissector_handle_t bgblink_handle;
    bgblink_handle = create_dissector_handle(dissect_bgblink, bgblink_handle);
    dissector_add_uint("tcp.port", BGBLINK_PORT, bgblink_handle);
}
