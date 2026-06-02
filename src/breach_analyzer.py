"""
Breach Data Analyzer Module
Analyzes public breach datasets for compromised credentials and patterns
"""

import pandas as pd
import os
import hashlib
import logging
from datetime import datetime
from collections import Counter, defaultdict
import config

logging.basicConfig(level=config.LOG_LEVEL, format=config.LOG_FORMAT)
logger = logging.getLogger(__name__)


class BreachAnalyzer:
    """
    Analyzes breach datasets to identify compromised credentials and patterns
    """
    
    def __init__(self):
        self.breach_data = None
        self.analysis_results = {}
        logger.info("BreachAnalyzer initialized")
    
    def load_breach_data(self, file_path):
        """
        Load breach data from CSV file
        
        Args:
            file_path (str): Path to breach dataset CSV
            
        Returns:
            pd.DataFrame: Loaded breach data
        """
        try:
            logger.info(f"Loading breach data from {file_path}")
            self.breach_data = pd.read_csv(file_path, nrows=config.MAX_BREACH_RECORDS)
            logger.info(f"Loaded {len(self.breach_data)} records from breach dataset")
            return self.breach_data
        except Exception as e:
            logger.error(f"Error loading breach data: {str(e)}")
            return None
    
    def analyze_breach_data(self, file_path):
        """
        Complete breach data analysis
        
        Args:
            file_path (str): Path to breach dataset
            
        Returns:
            dict: Analysis results with statistics and findings
        """
        self.load_breach_data(file_path)
        
        if self.breach_data is None:
            return None
        
        results = {
            'total_records': len(self.breach_data),
            'analysis_timestamp': datetime.now().isoformat(),
            'statistics': self._calculate_statistics(),
            'patterns': self._identify_patterns(),
            'duplicates': self._find_duplicates(),
            'breach_sources': self._identify_breach_sources()
        }
        
        self.analysis_results = results
        logger.info("Breach analysis completed successfully")
        return results
    
    def _calculate_statistics(self):
        """Calculate basic statistics from breach data"""
        stats = {
            'total_records': len(self.breach_data),
            'columns': list(self.breach_data.columns),
            'data_types': self.breach_data.dtypes.to_dict(),
            'memory_usage': str(self.breach_data.memory_usage(deep=True).sum())
        }
        
        # Calculate unique values
        for col in self.breach_data.columns:
            stats[f'unique_{col}'] = self.breach_data[col].nunique()
        
        return stats
    
    def _identify_patterns(self):
        """Identify patterns in breach data"""
        patterns = {}
        
        # Email domain analysis
        if 'email' in self.breach_data.columns:
            try:
                domains = self.breach_data['email'].str.split('@').str[1]
                patterns['top_domains'] = domains.value_counts().head(10).to_dict()
            except Exception as e:
                logger.warning(f"Could not analyze domains: {str(e)}")
        
        # Password pattern analysis
        if 'password' in self.breach_data.columns:
            patterns['password_stats'] = self._analyze_password_patterns()
        
        return patterns
    
    def _analyze_password_patterns(self):
        """Analyze password patterns in breach data"""
        passwords = self.breach_data['password'].dropna().astype(str)
        
        stats = {
            'total': len(passwords),
            'unique': passwords.nunique(),
            'avg_length': passwords.str.len().mean(),
            'max_length': passwords.str.len().max(),
            'min_length': passwords.str.len().min(),
            'contains_numbers': (passwords.str.contains(r'\d')).sum(),
            'contains_special': (passwords.str.contains(r'[!@#$%^&*]')).sum(),
            'contains_uppercase': (passwords.str.contains(r'[A-Z]')).sum(),
            'common_passwords': passwords.value_counts().head(10).to_dict()
        }
        
        return stats
    
    def _find_duplicates(self):
        """Find duplicate credentials across breaches"""
        duplicates = {
            'duplicate_records': len(self.breach_data[self.breach_data.duplicated()])
        }
        
        # Find duplicate emails if available
        if 'email' in self.breach_data.columns:
            duplicate_emails = self.breach_data[self.breach_data['email'].duplicated(keep=False)]
            duplicates['duplicate_emails'] = len(duplicate_emails)
            duplicates['most_repeated_emails'] = duplicate_emails['email'].value_counts().head(5).to_dict()
        
        return duplicates
    
    def _identify_breach_sources(self):
        """Identify breach sources/databases"""
        sources = {}
        
        if 'source' in self.breach_data.columns:
            sources['breach_sources'] = self.breach_data['source'].value_counts().to_dict()
        
        if 'date' in self.breach_data.columns or 'breach_date' in self.breach_data.columns:
            try:
                date_col = 'date' if 'date' in self.breach_data.columns else 'breach_date'
                sources['breaches_by_date'] = self.breach_data[date_col].value_counts().head(10).to_dict()
            except Exception as e:
                logger.warning(f"Could not analyze dates: {str(e)}")
        
        return sources
    
    def check_credential_in_breach(self, email, password=None):
        """
        Check if specific credential is in breach data
        
        Args:
            email (str): Email to check
            password (str, optional): Password to check
            
        Returns:
            dict: Match information
        """
        if self.breach_data is None:
            logger.warning("No breach data loaded")
            return {'found': False, 'matches': []}
        
        matches = []
        
        # Check email
        email_matches = self.breach_data[self.breach_data['email'].str.lower() == email.lower()]
        if len(email_matches) > 0:
            matches.extend(email_matches.to_dict('records'))
        
        # Check password if provided
        if password and 'password' in self.breach_data.columns:
            password_matches = self.breach_data[self.breach_data['password'] == password]
            if len(password_matches) > 0:
                matches.extend(password_matches.to_dict('records'))
        
        return {
            'found': len(matches) > 0,
            'match_count': len(matches),
            'matches': matches[:5]  # Return first 5 matches
        }
    
    def export_analysis(self, output_file):
        """
        Export analysis results to file
        
        Args:
            output_file (str): Path to output file
        """
        try:
            import json
            with open(output_file, 'w') as f:
                json.dump(self.analysis_results, f, indent=4, default=str)
            logger.info(f"Analysis exported to {output_file}")
        except Exception as e:
            logger.error(f"Error exporting analysis: {str(e)}")