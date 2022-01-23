# -*- coding: utf-8 -*-

import os
import sys
if getattr(sys, "frozen", False):
    app_path = os.path.dirname(sys.executable)
else:
    app_path = os.path.dirname(__file__)
try:
    import changeconf as cgc
    conf_sign = True
except ImportError:
    conf_sign = False


class GlobalVar(object):
    version = "1.4.3"
    cfg = None
    qt = False
    values = {}
    if conf_sign:
        type_chip = (cgc.lower_name, "bl602")
    else:
        type_chip = ("bl602", "bl602")
    
    
def _init():
    global _global_dict
    _global_dict = {}


def set_value(name, value):
    _global_dict[name] = value


def get_value(name, defValue=None):
    try:
        return _global_dict[name]
    except KeyError:
        return defValue


xtal_type = {}
xtal_type_ = {}
pll_clk = {}
encrypt_type = {}
key_sel = {}
sign_type = {}
cache_way_disable = {}
flash_clk_type = {}
crc_ignore = {}
hash_ignore = {}
img_type = {}
boot_src = {}
cpu_type = {}


# BL60X
xtal_type['bl60x'] = ["None", "32M", "38.4M", "40M", "26M", "52M"]
xtal_type_['bl60x'] = ["XTAL_" + item for item in xtal_type['bl60x']]
pll_clk['bl60x'] = ["50M", "120M", "160M", "192M"]
encrypt_type['bl60x'] = ["None", "AES128", "AES256", "AES192"]
key_sel['bl60x'] = ["0", "1", "2", "3"]
sign_type['bl60x'] = ["None", "ECC"]
cache_way_disable['bl60x'] = ["None", "OneWay", "TwoWay", "ThreeWay", "FourWay"]
flash_clk_type['bl60x'] = ["120M", "80M", "FDIV2", "96M", "XTAL", "50M", "Manual"]
crc_ignore['bl60x'] = ["False", "True"]
hash_ignore['bl60x'] = ["False", "True"]
img_type['bl60x'] = ["CPU0", "CPU1", "SingleCPU", "BLSP_Boot2", "RAW"]
boot_src['bl60x'] = ["Flash", "UART/SDIO"]
cpu_type['bl60x'] = ["CPU0", "CPU1"]

# BL602
xtal_type['bl602'] = ["None", "24M", "32M", "38.4M", "40M", "26M", "RC32M"]
xtal_type_['bl602'] = ["XTAL_" + item for item in xtal_type['bl602']]
pll_clk['bl602'] = ["RC32M", "XTAL", "48M", "120M", "160M", "192M"]
encrypt_type['bl602'] = ["None", "AES128", "AES256", "AES192"]
key_sel['bl602'] = ["0", "1", "2", "3"]
sign_type['bl602'] = ["None", "ECC"]
cache_way_disable['bl602'] = ["None", "OneWay", "TwoWay", "ThreeWay", "FourWay"]
flash_clk_type['bl602'] = ["120M", "XTAL", "48M", "80M", "BCLK", "96M", "Manual"]
crc_ignore['bl602'] = ["False", "True"]
hash_ignore['bl602'] = ["False", "True"]
img_type['bl602'] = ["SingleCPU", "BLSP_Boot2", "RAW"]
boot_src['bl602'] = ["Flash", "UART/SDIO"]

# BL702
xtal_type['bl702'] = ["None", "32M", "RC32M"]
xtal_type_['bl702'] = ["XTAL_" + item for item in xtal_type['bl702']]
pll_clk['bl702'] = ["RC32M", "XTAL", "57P6M", "96M", "144M"]
encrypt_type['bl702'] = ["None", "AES128", "AES256", "AES192"]
key_sel['bl702'] = ["0", "1", "2", "3"]
sign_type['bl702'] = ["None", "ECC"]
cache_way_disable['bl702'] = ["None", "OneWay", "TwoWay", "ThreeWay", "FourWay"]
flash_clk_type['bl702'] = ["144M", "XCLK", "57P6M", "72M", "BCLK", "96M", "Manual"]
crc_ignore['bl702'] = ["False", "True"]
hash_ignore['bl702'] = ["False", "True"]
img_type['bl702'] = ["SingleCPU", "BLSP_Boot2", "RAW"]
boot_src['bl702'] = ["Flash", "UART/USB"]

# BL606P
xtal_type['bl606p'] = ["None", "24M", "32M", "38.4M", "40M", "26M", "RC32M"]
xtal_type_['bl606p'] = [ "XTAL_" + item for item in xtal_type['bl606p'] ]
pll_clk['bl606p'] = ["RC32M", "XTAL", "160M wifipll", "192M wifipll", "240M wifipll", "320M ethpll", "300M cpupll"]
encrypt_type['bl606p'] = ["None", "AES128 CTR", "AES256 CTR", "AES192 CTR", "AES128 XTS"]
key_sel['bl606p'] = ["0", "1", "2", "3"]
sign_type['bl606p'] = ["None", "ECC"]
cache_way_disable['bl606p'] = ["None", "OneWay", "TwoWay", "ThreeWay", "FourWay"]
flash_clk_type['bl606p'] = ["120M wifipll", "XTAL", "120M cpupll", "80M wifipll", "BCLK", "96M wifipll", "Manual"]
crc_ignore['bl606p'] = ["False", "True"]
hash_ignore['bl606p'] = ["False", "True"]
img_type['bl606p'] = ["SingleCPU", "BLSP_Boot2", "RAW"]
boot_src['bl606p'] = ["Flash", "UART/USB"]
