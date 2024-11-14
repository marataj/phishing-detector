#  ---------------------------------------------------------------------------------------------------------------------
# Name:             settings
# Created By :      marataj
# Created Date:     2024-11-14
#  ---------------------------------------------------------------------------------------------------------------------

"""
Module containing project settings.

"""
import os
from dotenv import load_dotenv
from pathlib import Path

env_path = Path(__file__).resolve().parents[1] / '.env'
load_dotenv(env_path)

VIRUS_TOTAL_API_KEY = os.getenv("VIRUS_TOTAL_API_KEY")
GSB_API_KEY = os.getenv("GSB_API_KEY")
