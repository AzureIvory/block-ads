gcc main.c -o Code.exe ^
  -Os -flto ^
  -ffunction-sections -fdata-sections ^
  -Wl,--gc-sections ^
  -s ^
  -municode -mwindows
