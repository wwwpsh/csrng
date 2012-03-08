#!/bin/bash
#===============================================================================
#
#          FILE:  speed.sh
# 
#         USAGE:  ./speed.sh 
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
#       CREATED:  02/08/2012 01:30:42 PM CET
#      REVISION:  ---
#===============================================================================

\time ../utils/csprng-generate -v -a -d -n100m -f -o /dev/null
\time ../utils/csprng-generate -v -d    -n100m -f -o /dev/null

\time ../utils/csprng-generate -v -a    -n100m -f -o /dev/null
\time ../utils/csprng-generate -v       -n100m -f -o /dev/null


