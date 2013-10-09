/*
memgrep a tool to grep for data and strings accross processes on Windows

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

https://github.com/nccgroup/memgrep

Released under AGPL see LICENSE for more information
*/

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <Psapi.h>
#include <Aclapi.h>
#include <tlhelp32.h>
#include <wtsapi32.h>

