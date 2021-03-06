require 'rails_helper'

describe Idv::Flows::DocAuthFlow do
  include DocAuthHelper

  let(:user) { create(:user) }
  let(:new_session) { { doc_auth: {} } }
  let(:name) { :doc_auth }

  describe '#next_step' do
    it 'returns welcome as the first step' do
      subject = Idv::Flows::DocAuthFlow.new(new_session, user, name)
      result = subject.next_step

      expect(result).to eq('welcome')
    end

    it 'returns upload after the welcome step' do
      expect_next_step(:welcome, :upload)
    end

    it 'returns back_image after the front image step' do
      expect_next_step(:front_image, :back_image)
    end
  end

  describe '#handle' do
    it 'handles the next step and returns a form response object' do
      subject = Idv::Flows::DocAuthFlow.new(new_session, user, name)
      params = ActionController::Parameters.new(doc_auth: { ssn: '111111111' })
      expect_any_instance_of(Idv::Steps::SsnStep).to receive(:call).exactly(:once)

      result = subject.handle(:ssn, {}, params)
      expect(result.class).to eq(FormResponse)
      expect(result.success?).to eq(true)
    end
  end

  def expect_next_step(step, next_step)
    session = session_from_completed_flow_steps(step)
    subject = Idv::Flows::DocAuthFlow.new(session, user, name)
    result = subject.next_step

    expect(result.to_s).to eq(next_step.to_s)
  end
end
