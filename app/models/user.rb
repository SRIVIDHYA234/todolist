class User < ApplicationRecord
  has_many :tasks, dependent: :destroy
  before_save { email.downcase! }
  validates :name, presence: true, length: { maximum: 50 }
  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i
  validates :email, presence: true, length: { maximum: 255 },
                    format: { with: VALID_EMAIL_REGEX },
                    uniqueness: { case_sensitive: false }
  has_secure_password
  validates :password, presence: true, length: { minimum: 6 }

  def User.digest(string)
    cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST :
                                                  BCrypt::Engine.cost
    BCrypt::Password.create(string, cost: cost)
  end

  def encryption_key
    if password
      password + ENV.fetch("SECRET_KEY_BASE")
      padded_or_chopped(password)
    else
      ENV.fetch("SECRET_KEY_BASE")
      padded_or_chopped(ENV["SECRET_KEY_BASE"])
    end
  end

  private

  def padded_or_chopped(password)
    if password.length < 32
      " " * (32 - password.length) + password
    else
      password[0, 32]
    end
  end

  def set_random_url_key
    self.url_key = SecureRandom.hex(5) unless self.url_key.present?
  end
end
