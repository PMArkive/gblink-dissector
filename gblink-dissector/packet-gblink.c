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

//Command IDs
#define CMD_PROTOCOL_VERSION 1
#define CMD_JOYPAD           101
#define CMD_SEND_BYTE_MASTER 104
#define CMD_SEND_BYTE_SLAVE  105
#define CMD_TIMESTAMP        106
#define CMD_STATUS           108

static const value_string gblink_cmd_ids[] = {
    {CMD_PROTOCOL_VERSION, "Protocol version"},
    {CMD_JOYPAD,           "Joypad"},
    {CMD_SEND_BYTE_MASTER, "Send byte (master)"},
    {CMD_SEND_BYTE_SLAVE,  "Send byte (slave)"},
    {CMD_TIMESTAMP,        "Timestamp/Framecount sync"},
    {CMD_STATUS,           "Status"},
    {0, NULL}
};

//Forward declaration of dissector functions
void proto_register_gblink(void);
void proto_reg_handoff_gblink(void);
static void dissect_gblink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_gblink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item* ti;
    proto_tree* gblink_tree;
    guint8 id;
    guint32 timestamp;

    //Version info
    guint8 major_version, minor_version;

    //Joypad info
    guint8 button_num;
    const char* button_action;

    //Byte sent in transfer
    guint8 byte_sent, control;
    const char* speed;

    //Framecount info
    guint16 framecount;

    //Status
    const char* status;

    col_clear(pinfo->cinfo, COL_INFO);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GB Link");

    id = tvb_get_guint8(tvb,0);
    timestamp = tvb_get_ntohl(tvb,4);

    switch(id)
    {
        case CMD_PROTOCOL_VERSION:
            major_version = tvb_get_guint8(tvb,1);
            minor_version = tvb_get_guint8(tvb,2);
            col_append_fstr(pinfo->cinfo, COL_INFO, "Declaring protocol version %d.%d", major_version, minor_version);
            break;

        //TODO: figure out what buttons the numbers correspond to
        case CMD_JOYPAD:
            button_num = tvb_get_guint8(tvb,1) & 0x4;
            button_action = ((tvb_get_guint8(tvb,1) >> 2) & 0x1) ? "pushed" : "released";
            col_append_fstr(pinfo->cinfo, COL_INFO, "Button %d %s", button_num, button_action);
            break;

        case CMD_SEND_BYTE_MASTER:
            byte_sent = tvb_get_guint8(tvb,1);
            control = tvb_get_guint8(tvb,2);
            speed = ((control >> 1) & 0x1) ? "high speed" : "double speed";
            col_append_fstr(pinfo->cinfo, COL_INFO, "Master sent byte 0x%02x, %s, timestamp=%d", byte_sent, speed, timestamp);
            break;

        case CMD_SEND_BYTE_SLAVE:
            byte_sent = tvb_get_guint8(tvb,1);
            control = tvb_get_guint8(tvb,2);
            col_append_fstr(pinfo->cinfo, COL_INFO, "Slave sent byte 0x%02x, control=0x%02x", byte_sent, control);
            break;

        case CMD_TIMESTAMP:
            framecount = tvb_get_ntohs(tvb,2);
            if(tvb_get_guint8(tvb,1))
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Active transfer response, framecount=%d", framecount);
            }
            else col_append_fstr(pinfo->cinfo, COL_INFO, "Synchronization, framecount=%d, timestamp=%d", framecount, timestamp);
            break;

        //Specific to the BGB emulator
        case CMD_STATUS:
            status = (tvb_get_guint8(tvb,1) & 0x1) ? "Emulator is paused" : "Emulator is running";
            col_set_str(pinfo->cinfo, COL_INFO, status);
            break;

        default:
            col_set_str(pinfo->cinfo, COL_INFO, val_to_str(id, gblink_cmd_ids, "Unknown Command ID (%d)"));
            break;
    }

    if(tree)
    {
        ti = proto_tree_add_protocol_format(tree, proto_gblink, tvb, 0, 8,
             "Game Boy Link Cable Protocol");
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
                VALS(gblink_cmd_ids), 0x0,
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

    /*
     * As the name suggests, this protocol was originally implemented over
     * a cable, but it is used nowadays by the BGB Game Boy emulator, which
     * redirects all link cable output to TCP.
     */
    dissector_add_uint("tcp.port", GBLINK_PORT, gblink_handle);
}
