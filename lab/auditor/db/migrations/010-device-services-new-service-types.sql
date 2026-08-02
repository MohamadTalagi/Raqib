-- Idempotent. Safe to run repeatedly on a live database.
-- init.sql only runs on a fresh volume; this is the path for existing ones.

-- ===================================================================
-- Widens device_services.service_type's CHECK constraint to include the 4
-- new protocol types added alongside 5 non-camera device fixtures (smart
-- lock, industrial Modbus gateway, router/gateway UPnP, NVR RTSP, smart
-- speaker mDNS) - see lab/auditor/api/device_validation.py's SERVICE_TYPES,
-- the single source of truth this constraint must stay in sync with.
-- Additive only: every existing service_type value is still valid.
-- ===================================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'device_services_service_type_check'
    ) THEN
        ALTER TABLE device_services DROP CONSTRAINT device_services_service_type_check;
    END IF;
    ALTER TABLE device_services
        ADD CONSTRAINT device_services_service_type_check
        CHECK (service_type IN ('http', 'https', 'mqtt', 'mqtts', 'telnet', 'ssh', 'modbus', 'rtsp', 'upnp', 'mdns'));
END $$;
