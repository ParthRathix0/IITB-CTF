# Maze Escape - CTF Challenge Writeup

**Challenge Name:** GOREY
**CTF:** TrustCTF  
**Category:** Reverse Engineering  
**Flag:** `trustctf{y0uv3_35c4p3d_7h3_6l4d3_71m3_f0r_f4z3_7w0}`

---

## Challenge Overview

We're given a Linux binary `chall` that implements an interactive maze navigation challenge. The goal is to navigate from start (S) to end (E) in a hidden maze using directional commands, then the binary performs cryptographic transformations to reveal the flag.

---

## Initial Analysis

### Step 1: Binary Reconnaissance

```bash
file chall
# Output: chall: ELF 64-bit LSB executable, x86-64
```

The binary appears to be a Go binary based on the runtime symbols and structure.

![Binary file information](images/file_info.png)
*TODO: Add screenshot of file command output*

### Step 2: Extracting the Maze

Using `strings` to extract readable text and search for interesting patterns:

```bash
strings -a chall | egrep -i "flag|FLAG|CTF|Congrats|Good Job|Great Job|Surviving|escape|You (found|escaped)"
```

This revealed interesting strings including "Great Job on Surviving!!" and "It must drive you mad, trying to escape form something you can't see!"

![Strings output with interesting phrases](images/strings_output.png)
*TODO: Add screenshot of strings command output*

After exploring the binary further, I noticed long sequences of 0s and 1s. By examining the output and common phrases around these strings, I identified a pattern that looked like a serialized maze where:
- `0` = empty/walkable space
- `1` = wall
- `S` = start position
- `E` = end position

I extracted this data and saved it to `ans.txt`. The maze is **71x71** in size (5041 characters total).

![Extracted maze data visualization](images/maze_visualization.png)
*TODO: Add screenshot or visualization of the maze*

---

## Reverse Engineering with Ghidra

### Step 3: Decompiling the Binary

Opening `chall` in Ghidra and analyzing the main functions:

![Ghidra main window showing decompiled functions](images/ghidra_overview.png)
*TODO: Add screenshot of Ghidra with function list*

#### Key Functions Discovered:

1. **`main.main`** - The main game loop
2. **`main.db`** - Substitution cipher function
3. **`main.xb`** - XOR transformation function
4. **`main.ba`** - Binary-to-ASCII conversion function

### Step 4: Understanding the Navigation Logic

In `main.main`, I found the movement handling code:

![Decompiled movement logic in Ghidra](images/ghidra_movement_code.png)
*TODO: Add screenshot of the decompiled movement handling code*

```c
// For 4-character commands
if (extraout_RBX_00 == 4) {
    if (*extraout_RAX_02 == 0x54534145) {  // "EAST" (little-endian)
        pvVar9 = (void *)((int)pvVar6 + 2);  // Column + 2
    }
    else if (*extraout_RAX_02 == 0x54534557) {  // "WEST"
        pvVar9 = (void *)((int)pvVar6 + -2);  // Column - 2
    }
}

// For 5-character commands
else if (extraout_RBX_00 == 5) {
    if ((*extraout_RAX_02 == 0x54524f4e) && ((char)extraout_RAX_02[1] == 'H')) {  // "NORTH"
        piVar13 = (internal/abi.ITab *)((int)piVar2[-1].Fun + 6);
    }
    else if ((*extraout_RAX_02 == 0x54554f53) && ((char)extraout_RAX_02[1] == 'H')) {  // "SOUTH"
        piVar13 = (internal/abi.ITab *)((int)&piVar2->Inter + 2);
    }
}
```

**Critical Discovery:** The movement increments revealed that:
- **EAST**: moves column by **+2** (not +1!)
- **WEST**: moves column by **-2** (not -1!)
- **NORTH**: moves row by **-2** (not -1!)
- **SOUTH**: moves row by **+2** (not -1!)

This is unusual - most maze challenges use single-step movement, but this binary uses **double-step movement** in all directions!

---

## Solution Development

### Step 5: Parsing the Maze

Created a Python script to convert the binary string data into a 2D array:

```python
def convert_string_to_array(filename='ans.txt', rows=71, cols=71):
    with open(filename, 'r') as f:
        data = f.read().strip()
    
    # Convert to 2D array
    array = []
    for i in range(rows):
        row = []
        for j in range(cols):
            index = i * cols + j
            char = data[index]
            if char.isdigit():
                row.append(int(char))
            else:
                row.append(char)  # 'S' or 'E'
        array.append(row)
    
    return array
```

### Step 6: Initial Failed Attempt

My first attempt used a standard BFS solver with **single-step movement** (±1):

```python
directions = [
    (-1, 0, 'N'),   # North (up by 1) ❌
    (1, 0, 'S'),    # South (down by 1) ❌
    (0, 1, 'E'),    # East (right by 1) ❌
    (0, -1, 'W')    # West (left by 1) ❌
]
```

This found a 408-move solution that reached the end, but when tested:

```bash
python3 fast_input.py | ./chall
# Output: Great Job on Surviving!!
#         Too Slow!
```

![Failed attempt with single-step movement](images/failed_attempt.png)
*TODO: Add screenshot of the "Too Slow!" output*

The "Great Job on Surviving!!" confirmed I reached the end, but "Too Slow!" indicated something was wrong with the solution.

### Step 7: Correcting the Movement Logic

After re-examining the decompiled code more carefully, I realized **ALL movements use ±2**, not just horizontal ones!

Updated the BFS solver with **double-step movement**:

```python
def solve_maze_bfs_all_by_2(maze):
    directions = [
        (-2, 0, 'N'),   # North (up by 2) ✓
        (2, 0, 'S'),    # South (down by 2) ✓
        (0, 2, 'E'),    # East (right by 2) ✓
        (0, -2, 'W')    # West (left by 2) ✓
    ]
    
    # ... BFS implementation
    
    # Also check intermediate cells to ensure no walls
    for dr, dc, direction in directions:
        new_row, new_col = row + dr, col + dc
        
        # Check intermediate cell for walls
        if dr == 2:  # Moving SOUTH by 2
            if maze[row + 1][col] == 1:
                can_move = False
        elif dr == -2:  # Moving NORTH by 2
            if maze[row - 1][col] == 1:
                can_move = False
        # ... similar checks for EAST/WEST
```

### Step 8: Finding the Correct Solution

Running the corrected solver:

```bash
python3 solve_all_by_2.py
```

Output:
```
✓ Solution found with all movements by ±2!
Number of moves: 204

Solution:
SEENESSWSWSWSEENENESENENENNEESWSSSENNESSSWWWWSSSSEESSWWNWWWNWWNNWSSSSESSWSESWSEESESESSSEEESSSSWWSSWNNWWNWNWSSESWSEEESSSESSEENNWNWNEEEENWNENESSESENENWNEESESWSEESWWSSSEENWNEESESWSEEEEEEEESEENENESSEEEENNESSE
```

This produced a **204-move solution** (exactly half of the wrong 408-move solution!).

![Successful BFS solver output](images/bfs_success.png)
*TODO: Add screenshot of successful solver output*

---

## Cryptographic Pipeline

After reaching the end position, the binary processes the path through three functions:

1. **`main.db`** - Substitution cipher using lookup tables
2. **`main.xb`** - XOR transformation on the result
3. **`main.ba`** - Converts binary string (8-bit chunks) to ASCII

The "Too Slow!" string I initially saw was actually embedded in the substitution cipher data in `main.db`, not an error message. With the wrong path length, the transformations couldn't produce valid ASCII output.

---

## Getting the Flag

Converting the solution to full command words and piping to the binary:

```bash
cat solution_all_2.txt | sed 's/./&\n/g' | \
    sed 's/N/NORTH/g; s/S/SOUTH/g; s/E/EAST/g; s/W/WEST/g' | \
    grep -v '^$' | ./chall
```

Output:
```
It must drive you mad, trying to escape form something you can't see!

Great Job on Surviving!!
trustctf{y0uv3_35c4p3d_7h3_6l4d3_71m3_f0r_f4z3_7w0}
```

![Flag captured!](images/flag_output.png)
*TODO: Add screenshot of the flag being printed*

**Flag obtained!** 🎉

---

## Key Takeaways

1. **Read the decompiled code carefully** - The ±2 movement was clearly visible in the decompiled code, but easy to misinterpret initially.

2. **Don't assume standard behavior** - This challenge subverted the typical maze solver expectation of single-step movement.

3. **Test hypotheses quickly** - When the first solution didn't work despite "reaching the end," it was important to re-examine the movement logic rather than trying to optimize timing.

4. **Use multiple analysis techniques** - Combining `strings` output with Ghidra decompilation provided the complete picture.

5. **Watch for double-step validation** - When moving by 2, we needed to check intermediate cells for walls to ensure the path was actually valid.

---

## Tools Used

- **Ghidra** - For decompiling and analyzing the binary
- **strings** - For extracting the maze data
- **Python 3** - For maze solving (BFS algorithm)
- **bash/sed** - For input formatting

---

## Solution Files

- `ans.txt` - Extracted maze data (71×71 grid)
- `solve_all_by_2.py` - Final correct BFS solver with ±2 movement
- `solution_all_2.txt` - Winning solution path (204 moves)
- `corrected_input.py` - Script to convert solution to full command words

---

## Flag

```
trustctf{y0uv3_35c4p3d_7h3_6l4d3_71m3_f0r_f4z3_7w0}
```

*Translation: "You've escaped the glade time for phase two"*
