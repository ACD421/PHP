#!/bin/bash
# wp2_decode_matrix.sh - run the full 0-byte/short/truncated decode matrix (angle 3)
# usage: wp2_decode_matrix.sh [php|php_serialize|php_binary|all]
CL=$(cd "$(dirname "$0")" && pwd)
ART=/tmp/p2s_c2
mkdir -p "$ART/dec"
H="${1:-all}"

php_cases=(
  "c_empty|"
  "c_pipe|7C"
  "c_letter|61"
  "c_letter_pipe|617C"
  "c_pipe_val|7C693A313B"
  "c_kv|617C693A313B"
  "c_kv_trunc_tail|617C693A313B627C"
  "c_kv_trunc_val|617C693A31"
  "c_kv_trunc_val2|617C693A"
  "c_kv_trunc_val3|617C69"
  "c_high_key|80817C693A313B"
  "c_nul_key|6100627C693A313B"
  "c_nul_key_only|00007C693A313B"
  "c_key_pipe_in|617C627C693A313B"
  "c_long_key|$(python3 -c 'print("41"*65536 + "7C693A313B")')"
  "c_long_key_trunc|$(python3 -c 'print("41"*65536 + "7C")')"
  "c_obj_val|6F626A7C4F3A383A22737464436C617373223A303A7B7D"
  "c_arr_val|617C613A313A7B693A303B693A313B7D"
  "c_progress_key|75706C6F61645F70726F67726573735F787C693A313B"
  "c_two_pairs|617C693A313B627C693A323B"
  "c_neg_depth|617C693A2D313B"
  "c_big_len|617C733A34393533235303A22"
  "c_bignum|617C693A3932333337323033363835343737353830373B"
  "c_str_partial|617C733A333A226162"
  "c_bool|617C623A313B"
  "c_null_v|617C4E3B"
  "c_R|617C523A313B"
  "c_r_ref|617C723A313B"
)

bin_cases=(
  "b_empty|"
  "b_zeronamelen|00"
  "b_namelen1_noname|01"
  "b_namelen1_a|0161"
  "b_namelen1_a_val|0161693A313B"
  "b_namelen1_a_truncval|0161693A31"
  "b_namelen127_short|7F"
  "b_namelen127_nameonly|$(python3 -c 'print("7F" + "61"*127)')"
  "b_namelen127_full|$(python3 -c 'print("7F" + "61"*127 + "693A313B")')"
  "b_0x80|80"
  "b_0x80_val|80693A313B"
  "b_0xff|FF"
  "b_0xff_val|$(python3 -c 'print("FF" + "61"*127 + "693A313B")')"
  "b_0xff_shortval|$(python3 -c 'print("FF" + "61"*127 + "693A")')"
  "b_two_trunc2nd|0161693A313B02"
  "b_pipe_in_name|03617C62693A313B"
  "b_nul_in_name|03610062693A313B"
  "b_undef_flag|8300693A313B"
  "b_entry_then_garbage|0161693A313B58585858"
  "b_namelen2_partial|0261"
  "b_nested_val|0161613A313A7B733A313A2261223B693A313B7D"
)

ser_cases=(
  "s_empty|"
  "s_empty_arr|613A303A7B7D"
  "s_partial_arr|613A313A7B"
  "s_partial_arr2|613A313A7B733A333A22666F6F22"
  "s_partial_arr3|613A313A7B733A333A22666F6F223B693A31"
  "s_partial_arr4|613A313A7B733A333A22666F6F223B693A313B"
  "s_partial_arr5|613A313A7B733A333A22666F6F223B693A313B7D"
  "s_trunc_str|733A313A2261"
  "s_trunc_str2|733A313A"
  "s_trunc_obj|4F3A383A22737464436C617373223A313A7B733A313A2261223B693A313B"
  "s_trunc_obj2|4F3A383A22737464436C617373223A313A7B"
  "s_obj_no_brace|4F3A383A22737464436C617373223A303A7B"
  "s_nul_key|613A313A7B733A333A22006162223B693A313B7D"
  "s_pipe_key|613A313A7B733A333A22617C62223B693A313B7D"
  "s_big_len|733A3439353235303A2261"
  "s_huge_len|733A3932333337323033363835343737353830373A2261"
  "s_custom_obj|4F3A333A22586F626A223A323A7B733A313A2261223B733A313A2261223B7D"
  "s_nested_arr|613A313A7B613A313A7B613A313A7B613A313A7B693A313B7D7D7D7D"
  "s_ref|R:1;"
  "s_ref_bad|R:3930303B"
  "s_just_N|4E"
  "s_progress_val|613A313A7B733A32303A2275706C6F61645F70726F67726573735F78223B613A303A7B7D7D"
)

run_set() {
  local handler="$1"; shift
  local arrname="$1"
  for entry in "${arrname}"/*; do :; done 2>/dev/null
}

run_cases() {
  local handler="$1"; shift
  # remaining args: case arrays passed as "$@"
  local -a cases=("$@")
  for c in "${cases[@]}"; do
    name="${c%%|*}"; hex="${c#*|}"
    bash "$CL/wp2_decode.sh" "$handler" "$hex" "$name"
  done
}

if [ "$H" = "php" ] || [ "$H" = "all" ]; then run_cases php "${php_cases[@]}"; fi
if [ "$H" = "php_binary" ] || [ "$H" = "all" ]; then run_cases php_binary "${bin_cases[@]}"; fi
if [ "$H" = "php_serialize" ] || [ "$H" = "all" ]; then run_cases php_serialize "${ser_cases[@]}"; fi
echo MATRIX-DONE
