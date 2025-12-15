#!/bin/bash
#
# Cron Job Template for TOR Network Data Collection
# 
# Installation Instructions:
# 1. Edit this file and update the paths below
# 2. Make executable: chmod +x tor_cron_template.sh
# 3. Add to crontab: crontab -e
# 4. Add this line (runs hourly at minute 0):
#    0 * * * * /path/to/traffic-analysis-dashboard/tor_cron_template.sh >> /path/to/logs/tor_cron.log 2>&1
#
# For hourly collection with more control, use:
#    0 * * * * cd /path/to/traffic-analysis-dashboard && /path/to/.venv/bin/python tor_collector.py --collect >> data/tor_cron.log 2>&1
#

# ============================================================================
# Configuration - UPDATE THESE PATHS
# ============================================================================

# Path to your project directory
PROJECT_DIR="/Users/deekshithsk/Desktop/prime"

# Path to your Python virtual environment (if using one)
VENV_PATH="$PROJECT_DIR/.venv"

# Path to Python executable (use venv or system Python)
if [ -d "$VENV_PATH" ]; then
    PYTHON="$VENV_PATH/bin/python"
else
    PYTHON="python3"
fi

# Log file
LOG_FILE="$PROJECT_DIR/data/tor_cron.log"

# ============================================================================
# Execution
# ============================================================================

# Change to project directory
cd "$PROJECT_DIR" || exit 1

# Log start time
echo "========================================" >> "$LOG_FILE"
echo "TOR Collection Job - $(date)" >> "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"

# Run collector
$PYTHON tor_collector.py --collect >> "$LOG_FILE" 2>&1

# Optionally run cleanup weekly (uncomment if needed)
# if [ $(date +%u) -eq 1 ]; then  # Monday
#     echo "Running weekly cleanup..." >> "$LOG_FILE"
#     $PYTHON tor_collector.py --cleanup >> "$LOG_FILE" 2>&1
# fi

# Log completion
echo "Completed at $(date)" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

exit 0
