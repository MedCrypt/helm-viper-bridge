"""
Pydantic models for API request/response validation.
"""

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from enum import Enum


class FileType(str, Enum):
    """SBOM file type enumeration."""
    CDX = "CDX"
    SPDX = "SPDX"


# Request Models

class GetSbomRequest(BaseModel):
    """Request model for getting SBOM."""
    device_group_id: Optional[str] = Field(None, description="Viper device group ID")
    product_version_uuid: Optional[str] = Field(None, description="Helm product version UUID")


class UploadSbomRequest(BaseModel):
    """Request model for uploading SBOM."""
    device_group_id: Optional[str] = Field(None, description="Viper device group ID")
    product_version_uuid: Optional[str] = Field(None, description="Helm product version UUID")
    workspace_name: Optional[str] = Field(None, description="Helm workspace name (optional)")
    sbom_content: str = Field(..., description="Base64-encoded SBOM content")
    sbom_filename: Optional[str] = Field("sbom.json", description="SBOM filename")
    file_type: Optional[FileType] = Field(FileType.CDX, description="SBOM file type (CDX or SPDX)")


class ExportSbomRequest(BaseModel):
    """Request model for exporting SBOM."""
    product_name: str = Field(..., description="Product name in Helm")
    version: str = Field(..., description="Product version string")
    workspace_name: Optional[str] = Field(None, description="Helm workspace name (optional)")


class CreateProductRequest(BaseModel):
    """Request model for creating product."""
    product_name: str = Field(..., description="Product name")
    version: str = Field(..., description="Product version string")
    workspace_name: Optional[str] = Field(None, description="Helm workspace name (optional)")


class ViperSyncRequest(BaseModel):
    """Request model for Viper sync."""
    device_group_id: str = Field(..., description="Viper device group ID")
    product_name: str = Field(..., description="Product name in Helm")
    version: str = Field(..., description="Product version string")
    workspace_name: Optional[str] = Field(None, description="Helm workspace name (optional)")


class EmptyRequest(BaseModel):
    """Empty request model for endpoints that don't need input."""
    pass


# Response Models

class GetSbomResponse(BaseModel):
    """Response model for getting SBOM."""
    success: bool = Field(..., description="Success status")
    sbom: Dict[str, Any] = Field(..., description="CycloneDX SBOM content")
    product_name: str = Field(..., description="Product name")
    version: str = Field(..., description="Product version")
    product_uuid: str = Field(..., description="Product UUID")
    product_version_uuid: str = Field(..., description="Product version UUID")


class UploadSbomResponse(BaseModel):
    """Response model for uploading SBOM."""
    success: bool = Field(..., description="Success status")
    message: str = Field(..., description="Success message")
    product_name: str = Field(..., description="Product name")
    version: str = Field(..., description="Product version")
    product_uuid: str = Field(..., description="Product UUID")
    product_version_uuid: str = Field(..., description="Product version UUID")
    sbom_uploaded: bool = Field(..., description="Whether SBOM was uploaded")


class ExportSbomResponse(BaseModel):
    """Response model for exporting SBOM."""
    success: bool = Field(..., description="Success status")
    sbom: Dict[str, Any] = Field(..., description="CycloneDX SBOM content")
    product_name: str = Field(..., description="Product name")
    version: str = Field(..., description="Product version")
    file_path: str = Field(..., description="Path where SBOM was saved")


class CreateProductResponse(BaseModel):
    """Response model for creating product."""
    success: bool = Field(..., description="Success status")
    message: str = Field(..., description="Success message")
    product_name: str = Field(..., description="Product name")
    version: str = Field(..., description="Product version")
    product_uuid: str = Field(..., description="Product UUID")
    product_version_uuid: str = Field(..., description="Product version UUID")


class DeviceGroup(BaseModel):
    """Device group model."""
    id: str = Field(..., description="Device group ID")
    name: Optional[str] = Field(None, description="Device group name")
    sbomHelmId: Optional[str] = Field(None, description="Helm SBOM ID")


class MatchedDeviceGroup(BaseModel):
    """Matched device group with Helm info."""
    id: str = Field(..., description="Device group ID")
    cpe: Optional[List[str]] = Field(None, description="CPE strings")
    helmProductName: str = Field(..., description="Helm product name")
    helmProductVersionName: str = Field(..., description="Helm product version name")
    helmSbomId: str = Field(..., description="Helm product version UUID")


class ViperDeviceGroupsResponse(BaseModel):
    """Response model for listing Viper device groups."""
    success: bool = Field(..., description="Success status")
    device_groups: List[DeviceGroup] = Field(..., description="List of device groups")
    count: int = Field(..., description="Number of device groups")


class MatchedDeviceGroupsResponse(BaseModel):
    """Response model for matched device groups."""
    success: bool = Field(..., description="Success status")
    device_groups: List[MatchedDeviceGroup] = Field(..., description="List of matched device groups")
    count: int = Field(..., description="Number of matched device groups")


class ViperSyncResponse(BaseModel):
    """Response model for Viper sync."""
    success: bool = Field(..., description="Success status")
    message: str = Field(..., description="Success message")
    device_group_id: str = Field(..., description="Device group ID")
    product_name: str = Field(..., description="Product name")
    version: str = Field(..., description="Product version")
    product_uuid: str = Field(..., description="Product UUID")
    product_version_uuid: str = Field(..., description="Product version UUID")
    viper_updated: bool = Field(..., description="Whether Viper was updated")


class TestResponse(BaseModel):
    """Response model for test endpoint."""
    message: str = Field(..., description="Test message")
    authenticated: bool = Field(..., description="Authentication status")


class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str = Field(..., description="Server status")
    uptime_seconds: float = Field(..., description="Server uptime in seconds")
    internal_keys: int = Field(..., description="Number of internal API keys")
    external_keys: int = Field(..., description="Number of external API keys")
    rate_limit_global: int = Field(..., description="Global rate limit per minute")
    rate_limit_per_ip: int = Field(..., description="Per-IP rate limit per minute")


class ServerStatusResponse(BaseModel):
    """Response model for server status."""
    status: str = Field(..., description="Server status")
    message: str = Field(..., description="Status message")


class ErrorResponse(BaseModel):
    """Error response model."""
    error: str = Field(..., description="Error message")
    traceback: Optional[str] = Field(None, description="Stack trace (only in development)")


class ViperVulnSyncOptions(BaseModel):
    """Options for vulnerability sync."""
    include_resolved: bool = Field(False, description="Include resolved vulnerabilities")
    min_severity: str = Field("Low", description="Minimum severity to sync (Low, Medium, High, Critical)")


class ViperVulnSyncRequest(BaseModel):
    """Request model for Viper vulnerability bulk sync."""
    product_version_uuid: str = Field(..., description="Helm product version UUID to get vulnerabilities from")
    device_group_id: Optional[str] = Field(None, description="Optional device group ID to associate with")
    sync_options: Optional[ViperVulnSyncOptions] = Field(
        default_factory=ViperVulnSyncOptions,
        description="Sync options"
    )


class RequestVulnSyncRequest(BaseModel):
    """Request model for requesting vulnerability sync by device group ID."""
    device_group_id: str = Field(..., description="Viper device group ID to sync vulnerabilities for")
    sync_options: Optional[ViperVulnSyncOptions] = Field(
        default_factory=ViperVulnSyncOptions,
        description="Sync options"
    )


class ViperVulnSyncResponse(BaseModel):
    """Response model for Viper vulnerability bulk sync."""
    success: bool = Field(..., description="Success status")
    synced_count: int = Field(..., description="Number of vulnerabilities synced")
    failed_count: int = Field(..., description="Number of vulnerabilities that failed to sync")
    viper_vulnerabilities: List[Dict[str, Any]] = Field(..., description="Created vulnerabilities from Viper")
    errors: List[str] = Field(default_factory=list, description="List of errors encountered")


class ExternalVulnSyncRequest(BaseModel):
    """Request model for async webhook-based vulnerability sync across all matched device groups."""
    last_sync: Optional[str] = Field(None, description="ISO-8601 timestamp — only include vulns associated after this date")
    not_after: Optional[str] = Field(None, description="ISO-8601 timestamp — only include vulns associated before this date")
    page: int = Field(1, description="Starting page number (used in webhook response pagination)")
    pageSize: int = Field(500, description="Number of vulnerabilities per webhook page")
    webhook_url: str = Field(..., description="URL to POST paginated results to")


class ExternalVulnSyncAcceptedResponse(BaseModel):
    """Response model returned immediately (202) when an external vuln sync is accepted."""
    status: str = Field("accepted", description="Request status")
    message: str = Field(..., description="Human-readable status message")
    matched_device_groups: int = Field(..., description="Number of matched device groups that will be processed")
