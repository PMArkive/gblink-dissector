/*
 * Copyright (c) 2014 Nicholas Corgan (n.corgan@gmail.com)
 *
 * Distributed under the MIT License (MIT) (See accompanying file LICENSE.txt
 * or copy at http://opensource.org/licenses/MIT)
 */

#include <ctype.h>

#include <wireshark/config.h>
#include <epan/packet.h>

/*
 * Info: http://bgb.bircd.org/bgblink.html
 */

const gint GBLINK_PORT = 8765;

static int proto_gblink = -1;

//Packet fields
static int hf_gblink_b1 = -1; //Command
static int hf_gblink_b2 = -1;
static int hf_gblink_b3 = -1;
static int hf_gblink_b4 = -1;
static int hf_gblink_i1 = -1; //Timestamp

static gint ett_gblink = -1;

static const value_string gblink_cmd_ids[] = {
    {1, "Protocol version"},
    {101, "Joypad"},
    {104, "Send byte (master)"},
    {105, "Send byte (slave)"},
    {106, "Timestamp/Framecount sync"},
    {108, "Status"}
};

//Forward declaration of dissector functions
void proto_register_gblink(void);
void proto_reg_handoff_gblink(void);
static void dissect_gblink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_gblink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item* ti = NULL;
    proto_tree* gblink_tree = NULL;
    guint8 id;

    col_clear(pinfo->cinfo, COL_INFO);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GB Link");
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str(id, gblink_cmd_ids, "Unknown command ID '%c'"));

    if(tree)
    {
        ti = proto_tree_add_protocol_format(tree, proto_gblink, tvb, 0, 8, "Command ID = %c ", id);
        gblink_tree = proto_item_add_subtree(ti, ett_gblink);
        proto_tree_add_item(gblink_tree, hf_gblink_b1, tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(gblink_tree, hf_gblink_b2, tvb, 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(gblink_tree, hf_gblink_b3, tvb, 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(gblink_tree, hf_gblink_b4, tvb, 3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(gblink_tree, hf_gblink_i1, tvb, 4, 4, ENC_BIG_ENDIAN);
    }
}

void proto_register_gblink(void)
{
    static hf_register_info hf[] = {
        {
            &hf_gblink_b1,
            {
                "B1/Command", "gblink.b1",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                "Byte 1 / Link Command", HFILL
            }
        },
        {
            &hf_gblink_b2,
            {
                "B2", "gblink.b2",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                "Byte 2", HFILL
            }
        },
        {
            &hf_gblink_b3,
            {
                "B3", "gblink.b3",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                "Byte 3", HFILL
            }
        },
        {
            &hf_gblink_b4,
            {
                "B4", "gblink.b4",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                "Byte 4", HFILL
            }
        },
        {
            &hf_gblink_i1,
            {
                "I1/Timestamp", "gblink.i1",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                "Timestamp", HFILL
            }
        }
    };

    static gint *ett[] = {
        &ett_gblink
    };

    proto_gblink = proto_register_protocol("GB Link Cable Protocol", "GB Link", "gblink");
    proto_register_field_array(proto_gblink, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

//Handler registration
void proto_reg_handoff_gblink(void)
{
    static dissector_handle_t gblink_handle;
    gblink_handle = create_dissector_handle(dissect_gblink, proto_gblink);
    dissector_add_uint("tcp.port", GBLINK_PORT, gblink_handle);
}
