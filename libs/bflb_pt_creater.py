# -*- coding: utf-8 -*-
#  Copyright (C) 2021- BOUFFALO LAB (NANJING) CO., LTD.
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in all
#  copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#  SOFTWARE.


from libs import bflb_utils
from libs import bflb_toml as toml


class PtCreater(object):

    def __init__(self, config_file):
        self.parsed_toml = toml.load(config_file)
        self.entry_max = 16
        self.pt_new = False

    def __create_pt_table_do(self, lists, file):
        entry_table = bytearray(36 * self.entry_max)
        entry_cnt = 0
        for item in lists:
            entry_type = item["type"]
            entry_name = item["name"]
            entry_device = item["device"]
            entry_addr0 = item["address0"]
            entry_addr1 = item["address1"]
            entry_maxlen0 = item["size0"]
            entry_maxlen1 = item["size1"]
            entry_len = item["len"]
            entry_table[36 * entry_cnt + 0] = bflb_utils.int_to_2bytearray_l(entry_type)[0]
            if "activeindex" in item:
                entry_activeindex = item["activeindex"]
                entry_table[36 * entry_cnt +
                            2] = bflb_utils.int_to_2bytearray_l(entry_activeindex)[0]
            if len(entry_name) >= 8:
                bflb_utils.printf("Entry name is too long!")
                return False
            entry_table[36 * entry_cnt + 3:36 * entry_cnt + 3 +
                        len(entry_name)] = bytearray(entry_name, "utf-8") + bytearray(0) 
            entry_table[36 * entry_cnt + 12:36 * entry_cnt +
                        16] = bflb_utils.int_to_4bytearray_l(entry_addr0)
            entry_table[36 * entry_cnt + 16:36 * entry_cnt +
                        20] = bflb_utils.int_to_4bytearray_l(entry_addr1)
            entry_table[36 * entry_cnt + 20:36 * entry_cnt +
                        24] = bflb_utils.int_to_4bytearray_l(entry_maxlen0)
            entry_table[36 * entry_cnt + 24:36 * entry_cnt +
                        28] = bflb_utils.int_to_4bytearray_l(entry_maxlen1)
            entry_table[36 * entry_cnt + 28:36 * entry_cnt +
                        32] = bflb_utils.int_to_4bytearray_l(entry_len)
            if "age" in item:
                entry_age = item["age"]
                entry_table[36 * entry_cnt + 32:36 * entry_cnt +
                            36] = bflb_utils.int_to_4bytearray_l(entry_age)
            entry_cnt += 1
        # partition table header
        # 0x54504642
        pt_table = bytearray(16)
        pt_table[0] = 0x42
        pt_table[1] = 0x46
        pt_table[2] = 0x50
        pt_table[3] = 0x54
        pt_table[6:8] = bflb_utils.int_to_2bytearray_l(int(entry_cnt))
        pt_table[12:16] = bflb_utils.get_crc32_bytearray(pt_table[0:12])
        entry_table[36 * entry_cnt:36 * entry_cnt + 4] = bflb_utils.get_crc32_bytearray(
            entry_table[0:36 * entry_cnt])
        data = pt_table + entry_table[0:36 * entry_cnt + 4]
        fp = open(file, 'wb+')
        fp.write(data)
        fp.close()
        return True

    def create_pt_table(self, file):
        self.pt_new = True
        return self.__create_pt_table_do(self.parsed_toml["pt_entry"], file)

    def get_pt_table_addr(self):
        addr0 = self.parsed_toml["pt_table"]["address0"]
        addr1 = self.parsed_toml["pt_table"]["address1"]
        return addr0, addr1

    def construct_table(self):
        parcel = {}
        if self.pt_new is True:
            parcel['pt_new'] = True
        else:
            parcel['pt_new'] = False
        parcel['pt_addr0'] = self.parsed_toml["pt_table"]["address0"]
        parcel['pt_addr1'] = self.parsed_toml["pt_table"]["address1"]
        for tbl_item in self.parsed_toml["pt_entry"]:
            if tbl_item['name'] == 'factory':
                parcel['conf_addr'] = tbl_item['address0']
                parcel['conf_len'] = tbl_item['size0']
            if tbl_item['name'] == 'FW_CPU0':
                parcel['fw_cpu0_addr'] = tbl_item['address0']
                parcel['fw_cpu0_len'] = tbl_item['size0']
            if tbl_item['name'] == 'FW':
                parcel['fw_addr'] = tbl_item['address0']
                parcel['fw_len'] = tbl_item['size0']
            if tbl_item['name'] == 'media':
                parcel['media_addr'] = tbl_item['address0']
                parcel['media_len'] = tbl_item['size0']
            if tbl_item['name'] == 'mfg':
                parcel['mfg_addr'] = tbl_item['address0']
                parcel['mfg_len'] = tbl_item['size0']
        return parcel


if __name__ == '__main__':
    pt_helper = PtCreater("partition_cfg.toml")
    pt_helper.create_pt_table("partition_test.bin")
    pt_helper.get_pt_table_addr()
