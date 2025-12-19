import os
import logging
try:
    import boto3
    from botocore.exceptions import NoCredentialsError, PartialCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
except Exception:
    BOTO3_AVAILABLE = False

logger = logging.getLogger(__name__)

class CloudManager:
    """Handles production-ready cloud storage integrations."""
    
    def __init__(self):
        self.s3_client = self._init_s3()
        self.bucket_name = os.environ.get("AWS_S3_BUCKET")

    def _init_s3(self):
        if not BOTO3_AVAILABLE:
            return None
        try:
            return boto3.client(
                's3',
                aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY")
            )
        except Exception as e:
            logger.warning(f"S3 Initialization failed (Missing/Invalid Credentials): {e}")
            return None

    async def sync_file(self, file_path):
        """Upload a file to the configured S3 bucket."""
        if not self.s3_client or not self.bucket_name:
            return "Cloud sync skipped: S3 not configured."
        
        if not os.path.exists(file_path):
            return f"Error: {file_path} not found locally."

        try:
            filename = os.path.basename(file_path)
            self.s3_client.upload_file(file_path, self.bucket_name, filename)
            logger.info(f"Successfully synced {filename} to S3 bucket {self.bucket_name}")
            return f"Synced {filename} to the cloud."
        except (NoCredentialsError, PartialCredentialsError):
            return "Cloud sync failed: Credentials error."
        except Exception as e:
            logger.error(f"Cloud sync error: {e}")
            return f"Sync failed: {e}"

    async def sync_logs(self, log_file="automation.log"):
        """Convenience method to sync the main log file."""
        return await self.sync_file(log_file)
