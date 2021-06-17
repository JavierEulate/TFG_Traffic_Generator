from trex_stl_lib.api import *

def stats_sum_dict(stats, stats_sum):
    for key, value_dict in stats.items():
        if not stats_sum.get(key, False):
            stats_sum[key] = {}
        if type(value_dict) == dict:
            for key_key, value_value in value_dict.items():
                if type(value_value) == dict:	
                    for key_key_key, value_value_value in value_value.items():
                        if not stats_sum[key].get(key_key, False):
                            stats_sum[key][key_key] = {}
                        if not stats_sum[key][key_key].get(key_key_key, False):
                            stats_sum[key][key_key][key_key_key] = 0
                        stats_sum[key][key_key][key_key_key] += value_value_value
                else:
                    if not stats_sum[key].get(key_key, False):
                        stats_sum[key][key_key] = 0
                    new_value_to_update = value_value + stats_sum[key][key_key]
                    stats_sum[key][key_key] = new_value_to_update
    return stats_sum
    
 
def create_Field_Engine(ip_src1, ip_src2, op_src, ip_dst1, ip_dst2, op_dst):
    vm = STLScVmRaw( [ STLVmFlowVar(name="ip_src",
                                          min_value=ip_src1,
                                          max_value=ip_src2,
                                          size=4, op=op_src),

                   STLVmFlowVar(name="ip_dst",
                                          min_value=ip_dst1,
                                          max_value=ip_dst2,
                                          size=4, op=op_dst),

                   STLVmWrFlowVar(fv_name="ip_src", pkt_offset= "IP.src" ),
                   STLVmWrFlowVar(fv_name="ip_dst", pkt_offset= "IP.dst" ),

                   STLVmFixIpv4(offset = "IP"), # fix checksum
                  ]
               )
    return vm