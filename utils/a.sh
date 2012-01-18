#!/bin/bash
#===============================================================================
#
#          FILE:  a.sh
# 
#         USAGE:  ./a.sh 
# 
#   DESCRIPTION:  
# 
#       OPTIONS:  ---
#  REQUIREMENTS:  ---
#          BUGS:  ---
#         NOTES:  ---
#        AUTHOR:  Jiri Hladky (JH), hladky.jiri@gmail.com
#       COMPANY:  
#       VERSION:  1.0
#       CREATED:  01/17/2012 11:36:55 PM CET
#      REVISION:  ---
#===============================================================================

./csprng-generate -n 2000M | rngtest
