class SmsOtpSenderJob < ActiveJob::Base
  queue_as :sms

  def perform(code:, phone:, otp_created_at:)
    send_otp(TwilioService.new, code, phone) if otp_valid?(otp_created_at)
  end

  private

  def otp_valid?(otp_created_at)
    utc = ActiveSupport::TimeZone['UTC']
    utc.now < utc.parse(otp_created_at) + Devise.direct_otp_valid_for
  end

  def send_otp(twilio_service, code, phone)
    twilio_service.send_sms(
      to: phone,
      body: "#{code} is your #{APP_NAME} one-time passcode."
    )
  end
end
