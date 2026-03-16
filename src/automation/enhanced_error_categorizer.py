"""
Enhanced Error Categorization System
=====================================
Categorizes compilation errors into specific types for better handling.
Separates syntax errors, linker errors, and other categories.
"""
import re
from enum import Enum
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


class ErrorCategory(Enum):
    """Categories of compilation errors"""
    SYNTAX_ERROR = "syntax_error"
    LINKER_ERROR = "linker_error"
    MISSING_HEADER = "missing_header"
    UNDEFINED_SYMBOL = "undefined_symbol"
    TYPE_MISMATCH = "type_mismatch"
    DUPLICATE_SYMBOL = "duplicate_symbol"
    MISSING_ENTRY_POINT = "missing_entry_point"
    SYSTEM_REDEFINITION = "system_redefinition"
    INCLUDE_PATH = "include_path"
    LIBRARY_NOT_FOUND = "library_not_found"
    UNKNOWN = "unknown"


@dataclass
class CategorizedError:
    """A categorized compilation error"""
    category: ErrorCategory
    error_text: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    symbol_name: Optional[str] = None
    severity: str = "error"  # error, warning, note
    
    def to_dict(self) -> Dict:
        return {
            'category': self.category.value,
            'error_text': self.error_text,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'symbol_name': self.symbol_name,
            'severity': self.severity
        }


class EnhancedErrorCategorizer:
    """Categorize and analyze compilation errors"""
    
    # Regex patterns for error detection
    PATTERNS = {
        ErrorCategory.MISSING_HEADER: [
            r"fatal error:.*[:<](.+\.h)[>:]\s*:\s*No such file or directory",
            r"fatal error:.*Cannot open include file:\s*'(.+\.h)'",
            r"fatal error:.*'(.+\.h)'.*not found",
        ],
        ErrorCategory.UNDEFINED_SYMBOL: [
            r"undefined reference to\s+[`'](.+?)'",
            r"undefined symbol:\s*(.+)",
            r"error:\s+[`'](.+?)'\s+undeclared",
            r"error:\s+implicit declaration of function\s+[`'](.+?)'",
        ],
        ErrorCategory.DUPLICATE_SYMBOL: [
            r"multiple definition of\s+[`'](.+?)'",
            r"redefinition of\s+[`'](.+?)'",
            r"error:\s+redefinition of\s+[`'](.+?)'",
            r"error:\s+conflicting types for\s+[`'](.+?)'",
        ],
        ErrorCategory.MISSING_ENTRY_POINT: [
            r"undefined reference to\s+[`'](WinMain|main|_start)'",
            r"entry point.*not found",
            r"error:.*WinMain.*not defined",
        ],
        ErrorCategory.SYSTEM_REDEFINITION: [
            r"redefinition of\s+[`'](struct|union|enum)\s+(.+?)'",
            r"error:\s+redeclaration of\s+C\+\+\s+built-in type",
            r"conflicting types for.*built-in",
        ],
        ErrorCategory.TYPE_MISMATCH: [
            r"error:.*incompatible.*type",
            r"error:.*cannot convert",
            r"error:.*invalid conversion",
            r"error:.*type mismatch",
        ],
        ErrorCategory.LINKER_ERROR: [
            r"ld returned \d+ exit status",
            r"collect2\.exe: error: ld returned",
            r"cannot find -l(.+)",
            r"ld: library not found",
        ],
    }
    
    @classmethod
    def categorize_errors(cls, errors: List[str]) -> List[CategorizedError]:
        """
        Categorize a list of error messages.
        
        Args:
            errors: List of error message strings
            
        Returns:
            List of CategorizedError objects
        """
        categorized = []
        
        for error in errors:
            error = error.strip()
            if not error:
                continue
            
            # Extract file path and line number
            file_path, line_number = cls._extract_file_info(error)
            
            # Categorize the error
            category, symbol = cls._categorize_single_error(error)
            
            # Determine severity
            severity = cls._determine_severity(error)
            
            categorized.append(CategorizedError(
                category=category,
                error_text=error,
                file_path=file_path,
                line_number=line_number,
                symbol_name=symbol,
                severity=severity
            ))
        
        return categorized
    
    @classmethod
    def _extract_file_info(cls, error: str) -> Tuple[Optional[str], Optional[int]]:
        """Extract file path and line number from error message"""
        # Try various patterns for file:line:column format
        patterns = [
            r'([A-Za-z]:[/\\][\w/\\.]+):(\d+):',  # Windows path
            r'([\w/\\.-]+\.(?:c|cpp|h|hpp)):(\d+):',  # Unix path
            r'^(.+?):(\d+):',  # Generic path
        ]
        
        for pattern in patterns:
            match = re.search(pattern, error)
            if match:
                return match.group(1), int(match.group(2))
        
        return None, None
    
    @classmethod
    def _categorize_single_error(cls, error: str) -> Tuple[ErrorCategory, Optional[str]]:
        """Categorize a single error and extract symbol name if present"""
        # Check each category pattern
        for category, patterns in cls.PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, error, re.IGNORECASE)
                if match:
                    # Extract symbol name if captured
                    symbol = match.group(1) if match.groups() else None
                    return category, symbol
        
        # Check for syntax errors (fallback)
        if any(keyword in error.lower() for keyword in ['syntax error', 'expected', 'parse error']):
            return ErrorCategory.SYNTAX_ERROR, None
        
        return ErrorCategory.UNKNOWN, None
    
    @classmethod
    def _determine_severity(cls, error: str) -> str:
        """Determine error severity"""
        if 'warning:' in error.lower():
            return 'warning'
        elif 'note:' in error.lower():
            return 'note'
        return 'error'
    
    @classmethod
    def analyze_errors(cls, errors: List[str]) -> Dict:
        """
        Analyze errors and provide detailed statistics.
        
        Args:
            errors: List of error messages
            
        Returns:
            Dictionary with error analysis
        """
        categorized = cls.categorize_errors(errors)
        
        # Count by category
        category_counts = {}
        for cat_error in categorized:
            cat = cat_error.category.value
            category_counts[cat] = category_counts.get(cat, 0) + 1
        
        # Extract unique symbols by category
        symbols_by_category = {}
        for cat_error in categorized:
            if cat_error.symbol_name:
                cat = cat_error.category.value
                if cat not in symbols_by_category:
                    symbols_by_category[cat] = set()
                symbols_by_category[cat].add(cat_error.symbol_name)
        
        # Convert sets to lists for JSON serialization
        for cat in symbols_by_category:
            symbols_by_category[cat] = list(symbols_by_category[cat])
        
        # Separate by severity
        errors_only = [e for e in categorized if e.severity == 'error']
        warnings_only = [e for e in categorized if e.severity == 'warning']
        
        # Identify critical issues
        has_linker_errors = any(e.category == ErrorCategory.LINKER_ERROR for e in categorized)
        has_missing_entry = any(e.category == ErrorCategory.MISSING_ENTRY_POINT for e in categorized)
        has_duplicate_symbols = any(e.category == ErrorCategory.DUPLICATE_SYMBOL for e in categorized)
        has_system_redef = any(e.category == ErrorCategory.SYSTEM_REDEFINITION for e in categorized)
        
        return {
            'total_errors': len(errors_only),
            'total_warnings': len(warnings_only),
            'category_counts': category_counts,
            'symbols_by_category': symbols_by_category,
            'has_linker_errors': has_linker_errors,
            'has_missing_entry': has_missing_entry,
            'has_duplicate_symbols': has_duplicate_symbols,
            'has_system_redef': has_system_redef,
            'categorized_errors': [e.to_dict() for e in categorized],
        }
    
    @classmethod
    def get_fix_priority(cls, categorized_errors: List[CategorizedError]) -> List[ErrorCategory]:
        """
        Determine the order in which to fix error categories.
        
        Returns:
            List of ErrorCategory in priority order
        """
        # Priority order for fixing
        priority = [
            ErrorCategory.SYSTEM_REDEFINITION,     # Fix first - affects compilation
            ErrorCategory.MISSING_HEADER,           # Fix early - needed by other code
            ErrorCategory.DUPLICATE_SYMBOL,         # Fix before linking
            ErrorCategory.SYNTAX_ERROR,             # Fix syntax before semantics
            ErrorCategory.TYPE_MISMATCH,            # Fix type issues
            ErrorCategory.UNDEFINED_SYMBOL,         # Add missing symbols
            ErrorCategory.MISSING_ENTRY_POINT,      # Add entry point
            ErrorCategory.LINKER_ERROR,             # Fix linking issues last
        ]
        
        # Filter to only categories present in errors
        present_categories = set(e.category for e in categorized_errors)
        return [cat for cat in priority if cat in present_categories]
    
    @classmethod
    def separate_by_phase(cls, errors: List[str]) -> Dict[str, List[str]]:
        """
        Separate errors by compilation phase.
        
        Returns:
            Dictionary with 'compile_phase' and 'link_phase' errors
        """
        categorized = cls.categorize_errors(errors)
        
        compile_phase = []
        link_phase = []
        
        linker_categories = {
            ErrorCategory.LINKER_ERROR,
            ErrorCategory.MISSING_ENTRY_POINT,
            ErrorCategory.DUPLICATE_SYMBOL,
        }
        
        for error in categorized:
            if error.category in linker_categories:
                link_phase.append(error.error_text)
            else:
                compile_phase.append(error.error_text)
        
        return {
            'compile_phase': compile_phase,
            'link_phase': link_phase,
            'has_compile_errors': len(compile_phase) > 0,
            'has_link_errors': len(link_phase) > 0,
        }


def main():
    """Test error categorization"""
    test_errors = [
        "main.c:10:5: error: 'foo' undeclared",
        "main.c:15:10: fatal error: missing.h: No such file or directory",
        "undefined reference to `WinMain'",
        "multiple definition of `bar'",
        "error: redefinition of 'struct sockaddr'",
        "ld returned 1 exit status",
    ]
    
    print("Testing Enhanced Error Categorizer")
    print("=" * 60)
    
    categorized = EnhancedErrorCategorizer.categorize_errors(test_errors)
    
    print(f"\nCategorized {len(categorized)} errors:")
    for error in categorized:
        print(f"  [{error.category.value}] {error.error_text[:60]}...")
        if error.symbol_name:
            print(f"    Symbol: {error.symbol_name}")
    
    analysis = EnhancedErrorCategorizer.analyze_errors(test_errors)
    print(f"\nAnalysis:")
    print(f"  Total errors: {analysis['total_errors']}")
    print(f"  Categories: {analysis['category_counts']}")
    print(f"  Has linker errors: {analysis['has_linker_errors']}")
    print(f"  Has missing entry: {analysis['has_missing_entry']}")
    
    phases = EnhancedErrorCategorizer.separate_by_phase(test_errors)
    print(f"\nError Phases:")
    print(f"  Compile phase: {len(phases['compile_phase'])} errors")
    print(f"  Link phase: {len(phases['link_phase'])} errors")


if __name__ == "__main__":
    main()

