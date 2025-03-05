"""
State management for the Port Monitor system.
Handles persisting and recovering state between runs.
"""

import os
import json
import tempfile
import shutil
import logging
from datetime import datetime
from typing import Dict, Any, Optional

class StateManager:
    """Manages application state persistence and recovery"""
    
    def __init__(self, state_file_path: str):
        """Initialize the state manager with a state file path"""
        self.state_file = state_file_path
        self.state = self._load_state()
        
    def _load_state(self) -> Dict[str, Any]:
        """Load state from file"""
        if not os.path.exists(self.state_file):
            logging.info("No state file found, starting fresh")
            return {
                'last_scan_time': None,
                'current_scan_id': None,
                'scan_in_progress': False
            }
        
        try:
            with open(self.state_file, 'r') as f:
                state = json.load(f)
            logging.info(f"State loaded from {self.state_file}")
            return state
        except Exception as e:
            logging.error(f"Error loading state: {e}")
            return {
                'last_scan_time': None,
                'current_scan_id': None,
                'scan_in_progress': False
            }
            
    def save_state(self) -> bool:
        """Save current state to file, returns success/failure"""
        try:
            # Create a temporary file first to avoid corruption on system crash
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                json.dump(self.state, temp_file)
            
            # Replace the original file atomically
            shutil.move(temp_file.name, self.state_file)
            logging.debug(f"State saved to {self.state_file}")
            return True
        except Exception as e:
            logging.error(f"Error saving state: {e}")
            # Try to remove temp file if it exists
            try:
                if 'temp_file' in locals() and os.path.exists(temp_file.name):
                    os.remove(temp_file.name)
            except:
                pass
            return False
            
    def get_state(self) -> Dict[str, Any]:
        """Get the current state"""
        return self.state
        
    def set_scan_started(self, scan_id: str) -> None:
        """Set scan as started with the given ID"""
        self.state['current_scan_id'] = scan_id
        self.state['scan_in_progress'] = True
        self.state['scan_start_time'] = datetime.now().isoformat()
        self.save_state()
        
    def set_scan_completed(self, success: bool = True) -> None:
        """Set scan as completed"""
        self.state['scan_in_progress'] = False
        self.state['last_scan_time'] = datetime.now().isoformat()
        self.state['last_scan_status'] = 'success' if success else 'failed'
        self.save_state()
        
    def is_scan_in_progress(self) -> bool:
        """Check if a scan is in progress"""
        return self.state.get('scan_in_progress', False)
        
    def get_current_scan_id(self) -> Optional[str]:
        """Get the current scan ID if any"""
        return self.state.get('current_scan_id')
        
    def get_last_scan_time(self) -> Optional[str]:
        """Get the last scan time if any"""
        return self.state.get('last_scan_time')