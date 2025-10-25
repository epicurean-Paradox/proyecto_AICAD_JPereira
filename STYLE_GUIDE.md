# Project Style Guide

## Code Standards

### General Principles
- No emojis in any code, comments, documentation, commit messages, or output
- Clear, professional technical writing
- Explicit over implicit
- Fail fast with clear error messages
- Single responsibility principle

### Python Code Style

#### Imports
```python
# Standard library first
import sys
import os
from datetime import datetime
from typing import Dict, List, Optional

# Third-party libraries
import pandas as pd
from sqlalchemy import create_engine

# Local imports last
from shared.database.postgres_manager import PostgresManager
```

#### Function Documentation
```python
def calculate_health_score(account_id: str, lookback_days: int = 30) -> float:
    """
    Calculate account health score from multiple data sources.

    Args:
        account_id: Unique account identifier
        lookback_days: Number of days to analyze (default: 30)

    Returns:
        Health score between 0.0 and 100.0

    Raises:
        ValueError: If account_id is invalid
        DatabaseError: If database connection fails
    """
```

#### Error Handling
```python
# Good: Explicit error handling
try:
    result = fetch_data()
except DatabaseError as e:
    logger.error(f"Database fetch failed: {e}")
    raise
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    raise

# Bad: Silent failures
try:
    result = fetch_data()
except:
    pass
```

#### Logging
```python
# Use appropriate log levels
logger.debug("Detailed diagnostic information")
logger.info("Normal operation milestone reached")
logger.warning("Recoverable issue detected")
logger.error("Operation failed, needs attention")
logger.critical("System-level failure")

# Include context in error logs
logger.error(f"Failed to import account {account_id}: {error_msg}")
```

### SQL Style

#### Formatting
```sql
-- Clear, readable queries
SELECT
    account_id,
    account_name,
    health_score,
    created_at
FROM accounts
WHERE is_active = true
    AND health_score < 50.0
ORDER BY health_score ASC
LIMIT 10;

-- Use CTEs for complex queries
WITH active_accounts AS (
    SELECT account_id, health_score
    FROM accounts
    WHERE is_active = true
),
recent_activity AS (
    SELECT
        account_id,
        COUNT(*) as activity_count
    FROM engagement_metrics
    WHERE created_at >= NOW() - INTERVAL '30 days'
    GROUP BY account_id
)
SELECT
    a.account_id,
    a.health_score,
    COALESCE(r.activity_count, 0) as recent_activity
FROM active_accounts a
LEFT JOIN recent_activity r ON a.account_id = r.account_id;
```

#### Migrations
```sql
-- Migration: descriptive filename
-- File: shared/database/migrations/011_add_domain_to_accounts.sql

-- Add column with IF NOT EXISTS
ALTER TABLE accounts
ADD COLUMN IF NOT EXISTS domain VARCHAR(255);

-- Create index
CREATE INDEX IF NOT EXISTS idx_accounts_domain ON accounts(domain);

-- Log results
DO $$
DECLARE
    affected_rows INTEGER;
BEGIN
    SELECT COUNT(*) INTO affected_rows FROM accounts WHERE domain IS NOT NULL;
    RAISE NOTICE 'Migration complete: % accounts updated', affected_rows;
END $$;
```

### Documentation Standards

#### README Structure
```markdown
# Project Name

Clear one-sentence description.

## Architecture

Brief overview of system design.

## Setup

Step-by-step installation instructions.

## Usage

Common commands and workflows.

## Database Schema

Key tables and relationships.
```

#### Comment Standards
```python
# Good: Explain WHY, not WHAT
# Use domain matching first because it's more reliable than name matching
domain_match = find_by_domain(account)

# Bad: States the obvious
# Set x to 5
x = 5
```

#### Technical Documentation
- No marketing language
- No emojis or decorative elements
- Clear section headers
- Code examples with expected output
- Troubleshooting section with common issues

### Git Standards

#### Commit Messages
```
Add Salesloft integration with CSM engagement tracking

- Created database schema for Salesloft data (7 tables)
- Implemented import script with rate limiting
- Added account mapping with domain and name matching
- Fixed execute_update() errors in cadence imports

Migration: 011_add_domain_to_accounts.sql
```

#### Branch Naming
- `feature/salesloft-integration`
- `fix/cadence-import-error`
- `refactor/health-score-calculation`

### Testing Standards

#### Unit Tests
```python
def test_health_score_calculation():
    """Test health score combines three sources correctly."""
    # Arrange
    salesforce_score = 80.0
    sentiment_score = 60.0
    csm_score = 70.0

    # Act
    result = calculate_combined_health(salesforce_score, sentiment_score, csm_score)

    # Assert
    expected = (80.0 * 0.30) + (60.0 * 0.40) + (70.0 * 0.30)  # 69.0
    assert result == expected
```

#### Integration Tests
```python
def test_salesloft_import_end_to_end():
    """Test complete Salesloft import workflow."""
    # Setup test database
    db = PostgresManager(database='test_npm_dashboard')

    # Run import
    importer = SalesloftImporter(db)
    stats = importer.import_all()

    # Verify results
    assert stats['accounts']['new'] > 0
    assert stats['people']['new'] > 0

    # Cleanup
    db.close()
```

### Architecture Patterns

#### Database Access
```python
# Use PostgresManager for all database operations
db = PostgresManager(database='npm_dashboard')

# Query with parameters
results = db.execute_query(
    "SELECT * FROM accounts WHERE account_id = %s",
    params=(account_id,)
)

# Transaction support
with db.get_cursor() as cursor:
    cursor.execute("INSERT INTO ...")
    cursor.execute("UPDATE ...")
# Auto-commits on context exit
```

#### Configuration Management
```python
# Store credentials in environment variables
import os

SALESFORCE_USER = os.getenv('SALESFORCE_USERNAME')
SALESFORCE_PASS = os.getenv('SALESFORCE_PASSWORD')
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://localhost/npm_dashboard')
```

#### Error Recovery
```python
# Implement retry logic for API calls
from time import sleep

def fetch_with_retry(url, max_retries=3):
    for attempt in range(max_retries):
        try:
            return requests.get(url)
        except RequestException as e:
            if attempt == max_retries - 1:
                raise
            sleep(2 ** attempt)  # Exponential backoff
```

### Data Quality Standards

#### Input Validation
```python
def validate_account_id(account_id: str) -> None:
    """Validate account_id format and existence."""
    if not account_id:
        raise ValueError("account_id cannot be empty")

    if not isinstance(account_id, str):
        raise TypeError(f"account_id must be string, got {type(account_id)}")

    if len(account_id) > 255:
        raise ValueError(f"account_id too long: {len(account_id)} chars")
```

#### Data Sanitization
```python
# Clean domain values
domain = domain.lower().strip()
domain = domain.replace('https://', '').replace('http://', '')
domain = domain.replace('www.', '')
domain = domain.split('?')[0]  # Remove query params
domain = domain.rstrip('/')
```

### Performance Standards

#### Database Queries
- Use indexes for frequently queried columns
- Avoid SELECT * in production code
- Use LIMIT for development/testing
- Monitor slow query log

#### API Rate Limiting
```python
class RateLimiter:
    """Enforce API rate limits with exponential backoff."""

    def __init__(self, requests_per_minute: int):
        self.rpm = requests_per_minute
        self.min_interval = 60.0 / requests_per_minute
        self.last_request = 0

    def wait_if_needed(self):
        """Sleep if necessary to respect rate limit."""
        elapsed = time.time() - self.last_request
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_request = time.time()
```

## Output Formatting

### Console Output
```python
# Clear, structured logging
logger.info("=" * 80)
logger.info("SALESLOFT DATA IMPORT - START")
logger.info("=" * 80)
logger.info(f"Importing {len(accounts)} accounts...")
logger.info("Accounts: %d new, %d updated", new_count, updated_count)
logger.info("Import complete")
```

### Report Generation
```python
# Generate summary statistics
def generate_import_summary(stats: Dict) -> str:
    """Generate human-readable import summary."""
    lines = [
        "IMPORT SUMMARY",
        "-" * 80,
        f"Accounts:         {stats['accounts']['new']} new, {stats['accounts']['updated']} updated",
        f"People:           {stats['people']['new']} new, {stats['people']['updated']} updated",
        f"Meetings:         {stats['meetings']['new']} new",
        f"Duration:         {stats['duration']:.1f} seconds",
    ]
    return '\n'.join(lines)
```

## Security Standards

### Credential Management
- Never commit credentials to git
- Use environment variables for secrets
- Use AWS Secrets Manager or similar for production
- Rotate credentials regularly

### SQL Injection Prevention
```python
# Good: Parameterized queries
db.execute_query(
    "SELECT * FROM accounts WHERE account_name = %s",
    params=(user_input,)
)

# Bad: String concatenation
db.execute_query(f"SELECT * FROM accounts WHERE account_name = '{user_input}'")
```

### Access Control
- Use read-only database users for analytics
- Implement principle of least privilege
- Log all data access for audit trail

## Monitoring Standards

### Metrics to Track
- Import success/failure rates
- API response times
- Database query performance
- Data quality violations
- Error rates by type

### Alerting
- Critical errors: Immediate notification
- Warning conditions: Daily summary
- Performance degradation: Weekly review

## This Document
- Review quarterly
- Update when standards change
- All team members must follow
- Exceptions require justification
